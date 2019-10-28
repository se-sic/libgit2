/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "blame.h"

#include "git2/commit.h"
#include "git2/revparse.h"
#include "git2/revwalk.h"
#include "git2/tree.h"
#include "git2/diff.h"
#include "git2/blob.h"
#include "git2/signature.h"
#include "git2/mailmap.h"
#include "util.h"
#include "repository.h"
#include "blame_git.h"


static int hunk_byfinalline_search_cmp(const void *key, const void *entry)
{
	git_blame_hunk *hunk = (git_blame_hunk*)entry;

	size_t lineno = *(size_t*)key;
	size_t lines_in_hunk = hunk->lines_in_hunk;
	size_t final_start_line_number = hunk->final_start_line_number;

	if (lineno < final_start_line_number)
		return -1;
	if (lineno >= final_start_line_number + lines_in_hunk)
		return 1;
	return 0;
}

static int paths_cmp(const void *a, const void *b) { return git__strcmp((char*)a, (char*)b); }
static int hunk_cmp(const void *_a, const void *_b)
{
	git_blame_hunk *a = (git_blame_hunk*)_a,
						*b = (git_blame_hunk*)_b;

	if (a->final_start_line_number > b->final_start_line_number)
		return 1;
	else if (a->final_start_line_number < b->final_start_line_number)
		return -1;
	else
		return 0;
}

static bool hunk_ends_at_or_before_line(git_blame_hunk *hunk, size_t line)
{
	return line >= (hunk->final_start_line_number + hunk->lines_in_hunk - 1);
}

static bool hunk_starts_at_or_after_line(git_blame_hunk *hunk, size_t line)
{
	return line <= hunk->final_start_line_number;
}

static git_blame_hunk* new_hunk(
		size_t start,
		size_t lines,
		size_t orig_start,
		const char *path)
{
	git_blame_hunk *hunk = git__calloc(1, sizeof(git_blame_hunk));
	if (!hunk) return NULL;

	hunk->lines_in_hunk = lines;
	hunk->final_start_line_number = start;
	hunk->orig_start_line_number = orig_start;
	hunk->orig_path = path ? git__strdup(path) : NULL;

	return hunk;
}

static git_blame_hunk* dup_hunk(git_blame_hunk *hunk)
{
	git_blame_hunk *newhunk = new_hunk(
			hunk->final_start_line_number,
			hunk->lines_in_hunk,
			hunk->orig_start_line_number,
			hunk->orig_path);

	if (!newhunk)
		return NULL;

	git_oid_cpy(&newhunk->orig_commit_id, &hunk->orig_commit_id);
	git_oid_cpy(&newhunk->final_commit_id, &hunk->final_commit_id);
	newhunk->boundary = hunk->boundary;
	git_signature_dup(&newhunk->final_signature, hunk->final_signature);
	git_signature_dup(&newhunk->orig_signature, hunk->orig_signature);
	return newhunk;
}

static void free_hunk(git_blame_hunk *hunk)
{
	git__free((void*)hunk->orig_path);
	git_signature_free(hunk->final_signature);
	git_signature_free(hunk->orig_signature);
	git__free(hunk);
}

/* Starting with the hunk that includes start_line, shift all following hunks'
 * final_start_line by shift_by lines */
static void shift_hunks_by(git_vector *v, size_t start_line, int shift_by)
{
	size_t i;

	if (!git_vector_bsearch2(&i, v, hunk_byfinalline_search_cmp, &start_line)) {
		for (; i < v->length; i++) {
			git_blame_hunk *hunk = (git_blame_hunk*)v->contents[i];
			hunk->final_start_line_number += shift_by;
		}
	}
}

git_blame* git_blame__alloc(
	git_repository *repo,
	git_blame_options opts,
	const char *path)
{
	git_blame *gbr = git__calloc(1, sizeof(git_blame));
	if (!gbr)
		return NULL;

	gbr->repository = repo;
	gbr->options = opts;

	if (git_vector_init(&gbr->hunks, 8, hunk_cmp) < 0 ||
		git_vector_init(&gbr->paths, 8, paths_cmp) < 0 ||
		(gbr->path = git__strdup(path)) == NULL ||
		git_vector_insert(&gbr->paths, git__strdup(path)) < 0)
	{
		git_blame_free(gbr);
		return NULL;
	}

	if (opts.flags & GIT_BLAME_USE_MAILMAP &&
	    git_mailmap_from_repository(&gbr->mailmap, repo) < 0) {
		git_blame_free(gbr);
		return NULL;
	}

	return gbr;
}

void git_blame_free(git_blame *blame)
{
	size_t i;
	git_blame_hunk *hunk;

	if (!blame) return;

	git_vector_foreach(&blame->hunks, i, hunk)
		free_hunk(hunk);
	git_vector_free(&blame->hunks);

	git_vector_free_deep(&blame->paths);

	git_array_clear(blame->line_index);

	git_mailmap_free(blame->mailmap);

	git__free(blame->path);
	git_blob_free(blame->final_blob);
	git__free(blame);
}

uint32_t git_blame_get_hunk_count(git_blame *blame)
{
	assert(blame);
	return (uint32_t)blame->hunks.length;
}

const git_blame_hunk *git_blame_get_hunk_byindex(git_blame *blame, uint32_t index)
{
	assert(blame);
	return (git_blame_hunk*)git_vector_get(&blame->hunks, index);
}

const git_blame_hunk *git_blame_get_hunk_byline(git_blame *blame, size_t lineno)
{
	size_t i, new_lineno = lineno;
	assert(blame);

	if (!git_vector_bsearch2(&i, &blame->hunks, hunk_byfinalline_search_cmp, &new_lineno)) {
		return git_blame_get_hunk_byindex(blame, (uint32_t)i);
	}

	return NULL;
}

static int normalize_options(
		git_blame_options *out,
		const git_blame_options *in,
		git_repository *repo)
{
	git_blame_options dummy = GIT_BLAME_OPTIONS_INIT;
	if (!in) in = &dummy;

	memcpy(out, in, sizeof(git_blame_options));

	/* No newest_commit => HEAD */
	if (git_oid_is_zero(&out->newest_commit)) {
		if (git_reference_name_to_id(&out->newest_commit, repo, "HEAD") < 0) {
			return -1;
		}
	}

	/* min_line 0 really means 1 */
	if (!out->min_line) out->min_line = 1;
	/* max_line 0 really means N, but we don't know N yet */

	/* Fix up option implications */
	if (out->flags & GIT_BLAME_TRACK_COPIES_ANY_COMMIT_COPIES)
		out->flags |= GIT_BLAME_TRACK_COPIES_SAME_COMMIT_COPIES;
	if (out->flags & GIT_BLAME_TRACK_COPIES_SAME_COMMIT_COPIES)
		out->flags |= GIT_BLAME_TRACK_COPIES_SAME_COMMIT_MOVES;
	if (out->flags & GIT_BLAME_TRACK_COPIES_SAME_COMMIT_MOVES)
		out->flags |= GIT_BLAME_TRACK_COPIES_SAME_FILE;

	return 0;
}

static git_blame_hunk *split_hunk_in_vector(
		git_vector *vec,
		git_blame_hunk *hunk,
		size_t rel_line,
		bool return_new)
{
	size_t new_line_count;
	git_blame_hunk *nh;

	/* Don't split if already at a boundary */
	if (rel_line <= 0 ||
	    rel_line >= hunk->lines_in_hunk)
	{
		return hunk;
	}

	new_line_count = hunk->lines_in_hunk - rel_line;
	nh = new_hunk(hunk->final_start_line_number + rel_line, new_line_count,
			hunk->orig_start_line_number + rel_line, hunk->orig_path);

	if (!nh)
		return NULL;

	git_oid_cpy(&nh->final_commit_id, &hunk->final_commit_id);
	git_oid_cpy(&nh->orig_commit_id, &hunk->orig_commit_id);

	/* Adjust hunk that was split */
	hunk->lines_in_hunk -= new_line_count;
	git_vector_insert_sorted(vec, nh, NULL);
	{
		git_blame_hunk *ret = return_new ? nh : hunk;
		return ret;
	}
}

/*
 * Construct a list of char indices for where lines begin
 * Adapted from core git:
 * https://github.com/gitster/git/blob/be5c9fb9049ed470e7005f159bb923a5f4de1309/builtin/blame.c#L1760-L1789
 */
static int index_blob_lines(git_blame *blame)
{
    const char *buf = blame->final_buf;
    git_off_t len = blame->final_buf_size;
    int num = 0, incomplete = 0, bol = 1;
    size_t *i;

    if (len && buf[len-1] != '\n')
        incomplete++; /* incomplete line at the end */
    while (len--) {
        if (bol) {
            i = git_array_alloc(blame->line_index);
            GIT_ERROR_CHECK_ALLOC(i);
            *i = buf - blame->final_buf;
            bol = 0;
        }
        if (*buf++ == '\n') {
            num++;
            bol = 1;
        }
    }
    i = git_array_alloc(blame->line_index);
    GIT_ERROR_CHECK_ALLOC(i);
    *i = buf - blame->final_buf;
    blame->num_lines = num + incomplete;
    return blame->num_lines;
}

static git_blame_hunk* hunk_from_entry(git_blame__entry *e, git_blame *blame)
{
	git_blame_hunk *h = new_hunk(
			e->lno+1, e->num_lines, e->s_lno+1, e->suspect->path);

	if (!h)
		return NULL;

	git_oid_cpy(&h->final_commit_id, git_commit_id(e->suspect->commit));
	git_oid_cpy(&h->orig_commit_id, git_commit_id(e->suspect->commit));
	git_commit_author_with_mailmap(
		&h->final_signature, e->suspect->commit, blame->mailmap);
	git_signature_dup(&h->orig_signature, h->final_signature);
	h->boundary = e->is_boundary ? 1 : 0;
	return h;
}

static int load_blob(git_blame *blame)
{
	int error;

	if (blame->final_blob) return 0;

	error = git_commit_lookup(&blame->final, blame->repository, &blame->options.newest_commit);
	if (error < 0)
		goto cleanup;
	error = git_object_lookup_bypath((git_object**)&blame->final_blob,
			(git_object*)blame->final, blame->path, GIT_OBJECT_BLOB);

cleanup:
	return error;
}

static int blame_internal(git_blame *blame)
{
	int error;
	git_blame__entry *ent = NULL;
	git_blame__origin *o;

	if ((error = load_blob(blame)) < 0 ||
	    (error = git_blame__get_origin(&o, blame, blame->final, blame->path)) < 0)
		goto cleanup;
	blame->final_buf = git_blob_rawcontent(blame->final_blob);
	blame->final_buf_size = git_blob_rawsize(blame->final_blob);

	ent = git__calloc(1, sizeof(git_blame__entry));
	GIT_ERROR_CHECK_ALLOC(ent);

	ent->num_lines = index_blob_lines(blame);
	ent->lno = blame->options.min_line - 1;
	ent->num_lines = ent->num_lines - blame->options.min_line + 1;
	if (blame->options.max_line > 0)
		ent->num_lines = blame->options.max_line - blame->options.min_line + 1;
	ent->s_lno = ent->lno;
	ent->suspect = o;

	blame->ent = ent;

	error = git_blame__like_git(blame, blame->options.flags);

cleanup:
	for (ent = blame->ent; ent; ) {
		git_blame__entry *e = ent->next;
		git_blame_hunk *h = hunk_from_entry(ent, blame);

		git_vector_insert(&blame->hunks, h);

		git_blame__free_entry(ent);
		ent = e;
	}

	return error;
}

typedef struct git_blame_workdir_diff_entry
{
	size_t old_start;
	size_t old_lines;
	size_t new_start;
	size_t new_lines;
} git_blame_workdir_diff_entry;

static git_blame_workdir_diff_entry *git_blame_workdir_diff_entry__alloc(
		size_t old_start,
		size_t old_lines,
		size_t new_start,
		size_t new_lines)
{
	git_blame_workdir_diff_entry *entry =
		git__calloc(1, sizeof(git_blame_workdir_diff_entry));
	if (!entry)
		return NULL;

	entry->old_start = old_start;
	entry->old_lines = old_lines;
	entry->new_start = new_start;
	entry->new_lines = new_lines;

	return entry;
}

static void git_blame_workdir_diff_entry__free(git_blame_workdir_diff_entry *entry)
{
	git__free(entry);
}

static int git_blame_workdir_diff_entry_cmp(const void *_a, const void *_b)
{
	git_blame_workdir_diff_entry *a = (git_blame_workdir_diff_entry *)_a;
	git_blame_workdir_diff_entry *b = (git_blame_workdir_diff_entry *)_b;

	if (a->old_start > b->old_start)
		return 1;
	else if (a->old_start < b->old_start)
		return -1;
	else
		return 0;
}

typedef struct git_blame_workdir_diff {
	git_vector entries;
} git_blame_workdir_diff;

static void git_blame_workdir_diff__free(git_blame_workdir_diff *diff)
{
	size_t i;
	git_blame_workdir_diff_entry *diff_entry;

	if (!diff)
		return;

	git_vector_foreach(&diff->entries, i, diff_entry)
			git_blame_workdir_diff_entry__free(diff_entry);
	git_vector_free(&diff->entries);

	git__free(diff);
}

static git_blame_workdir_diff *git_blame_workdir_diff__alloc()
{
	git_blame_workdir_diff *diff = git__calloc(1, sizeof(git_blame_workdir_diff));

	if (!diff)
		return NULL;

	if (git_vector_init(&diff->entries, 8, git_blame_workdir_diff_entry_cmp)
			< 0) {
		git_blame_workdir_diff__free(diff);
		return NULL;
	}

	return diff;
}

static int process_workdir_diff_hunk(
		const git_diff_delta *delta,
		const git_diff_hunk *hunk,
		void *payload)
{
	git_blame_workdir_diff_entry *entry;
	git_blame_workdir_diff *wd_diff = (git_blame_workdir_diff *)payload;

	if (delta->status & GIT_DELTA_MODIFIED) {
		entry = git_blame_workdir_diff_entry__alloc(hunk->old_start,
				hunk->old_lines, hunk->new_start, hunk->new_lines);
		if (!entry)
			return GIT_ERROR;
		git_vector_insert_sorted(&wd_diff->entries, entry, NULL);
	}

	return 0;
}

static int remove_lines_from_hunk_vector(
		git_vector *vec,
		size_t start_lineno,
		size_t num_lines)
{
	git_blame_hunk *cur_hunk;
	size_t cur_hunk_index;
	size_t removable_lines;
	bool shift_node;

	if (num_lines == 0)
		return 0;

	if (git_vector_bsearch2(&cur_hunk_index, vec, hunk_byfinalline_search_cmp,
			&start_lineno))
		return GIT_ENOTFOUND;

	while (num_lines > 0) {
		cur_hunk = (git_blame_hunk*)git_vector_get(vec, cur_hunk_index);
		/* check if remove from beginning of hunk or middle */
		if (start_lineno >= cur_hunk->final_start_line_number) {
			/* remove from the middle of the hunk */
			removable_lines = (cur_hunk->final_start_line_number +
					cur_hunk->lines_in_hunk) - start_lineno;
			shift_node = false;
		} else {
			/* remove from the beginning of the hunk */
			removable_lines = cur_hunk->lines_in_hunk;
			shift_node = true;
		}

		if (removable_lines > num_lines)
			removable_lines = num_lines;

		cur_hunk->lines_in_hunk -= removable_lines;
		num_lines -= removable_lines;

		if (shift_node)
			cur_hunk->final_start_line_number += removable_lines;

		if (cur_hunk->lines_in_hunk == 0)
			git_vector_remove(vec, cur_hunk_index);
		else
			cur_hunk_index++;
	}

	return 0;
}

static int merge_blame_workdir_diff(
		git_blame *blame,
		git_blame_workdir_diff *wd_diff)
{
	int error = -1;
	size_t i;
	git_blame_workdir_diff_entry *diff_entry;
	long total_shift_count = 0; /* offset of how much we have shifted so far */
	size_t old_hunk_index;
	git_blame_hunk *old_hunk;
	git_blame_hunk *split_hunk;
	int diff_entry_delta;
	git_blame_hunk *nhunk;
	size_t shift_hunk_index;
	git_blame_hunk *shift_hunk;
	git_signature *sig_uncommitted;

	git_signature_now(&sig_uncommitted, "Not Committed Yet", "not.committed.yet");

	git_vector_foreach(&wd_diff->entries, i, diff_entry) {
		nhunk = NULL;

		/* shift old_start by the number of lines that have been added/removed by
		 * previous diff_entries
		*/
		diff_entry->old_start += total_shift_count;

		if (diff_entry->new_lines > 0) {
			/* lines are added, so we need to create a new hunk */
			nhunk = new_hunk(diff_entry->new_start, diff_entry->new_lines,
					diff_entry->new_start, blame->path);
			if (!nhunk)
				goto on_error;
			git_signature_dup(&nhunk->final_signature, sig_uncommitted);
			git_signature_dup(&nhunk->orig_signature, sig_uncommitted);
		}

		/* Get the old hunk that is modified by the diff_entry and split it if
		 * necessary.
		*/
		git_vector_bsearch2(&old_hunk_index, &blame->hunks,
				hunk_byfinalline_search_cmp, &diff_entry->old_start);
		old_hunk = (git_blame_hunk*)git_blame_get_hunk_byindex(blame,
				old_hunk_index);
		assert(old_hunk && "Could not find hunk.");

		if (diff_entry->new_lines >= diff_entry->old_lines) {
			diff_entry_delta = diff_entry->new_lines - diff_entry->old_lines;
		} else {
			diff_entry_delta = diff_entry->old_lines - diff_entry->new_lines;
			diff_entry_delta = -diff_entry_delta;
		}

		/* Check if we need to split the old hunk.
		 * This is the case if the modification is within the hunk.
		 * We do not need to split if the diff_entry only removes lines and does
		 * not add/modify any lines.
		*/
		if (diff_entry->old_start >= old_hunk->final_start_line_number &&
				diff_entry->old_start < (old_hunk->final_start_line_number +
				old_hunk->lines_in_hunk - 1) && diff_entry->new_lines > 0) {
			split_hunk = split_hunk_in_vector(&blame->hunks, old_hunk,
					diff_entry->old_start - (old_hunk->final_start_line_number - 1),
					true);
			if (!split_hunk)
				goto on_error;
		}

		/* Check if we need to remove lines from the old hunk */
		if (diff_entry->old_lines > 0) {
			error = remove_lines_from_hunk_vector(&blame->hunks,
					diff_entry->old_start, diff_entry->old_lines);
			assert(error == 0 && "Could not find hunk to remove lines from.");
		}

		/* Shift subsequent hunks if necessary */
		if (diff_entry_delta != 0) {
			shift_hunk_index = old_hunk_index;
			for (; shift_hunk_index < blame->hunks.length; shift_hunk_index++) {
				shift_hunk = (git_blame_hunk*)blame->hunks.contents[shift_hunk_index];
				if (shift_hunk->final_start_line_number > diff_entry->old_start) {
					shift_hunk->final_start_line_number += diff_entry_delta;
				}
			}
			total_shift_count += diff_entry_delta;
		}

		/* insert new hunk if there is one (only if hunk adds lines) */
		if (nhunk) {
			if ((error = git_vector_insert_sorted(&blame->hunks, nhunk, NULL)) < 0)
				goto on_error;
		}
	}

	return 0;

on_error:
	free_hunk(nhunk);
	return error;
}

static int git_blame_new_file(git_blame *blame)
{
	int error;
	git_oid oid;
	git_blame_hunk *nhunk = NULL;

	git_signature *sig_uncommitted;
	git_signature_now(&sig_uncommitted, "Not Committed Yet", "not.committed.yet");

	if ((error = git_blob_create_fromworkdir(
					&oid, blame->repository, blame->path)) < 0)
		return error;
	if ((error = git_blob_lookup(
					&blame->final_blob, blame->repository, &oid)) < 0)
		return error;
	blame->final_buf = git_blob_rawcontent(blame->final_blob);
	blame->final_buf_size = git_blob_rawsize(blame->final_blob);

	index_blob_lines(blame);

	nhunk = new_hunk(1, blame->num_lines, 1, blame->path);
	if (!nhunk) {
		free_hunk(nhunk);
		return GIT_ERROR;
	}
	git_signature_dup(&nhunk->final_signature, sig_uncommitted);
	git_signature_dup(&nhunk->orig_signature, sig_uncommitted);

	git_vector_insert(&blame->hunks, nhunk);

	return 0;
}

static int update_blame_with_uncommitted_changes(git_blame *blame)
{
	int error;
	git_object *obj = NULL;
	git_tree *tree = NULL;
	git_diff_options diff_options;
	git_strarray diff_file_paths = {0};
	git_diff *diff = NULL;
	git_blame_workdir_diff *wd_diff = NULL;
	git_oid oid;

	if ((error = git_revparse_single(&obj, blame->repository, "HEAD^{tree}")) < 0)
		goto on_error;

	if ((error = git_tree_lookup(&tree, blame->repository, git_object_id(obj)))
			< 0)
		goto on_error;

	if ((error = git_diff_init_options(&diff_options, GIT_DIFF_OPTIONS_VERSION))
			< 0)
		goto on_error;

	diff_file_paths.count = 1;
	diff_file_paths.strings = malloc(sizeof(char *));
	if (!diff_file_paths.strings)
		goto on_error;
	diff_file_paths.strings[0] = blame->path;

	diff_options.pathspec = diff_file_paths;
	diff_options.max_size = 0;
	diff_options.context_lines = 0;
	diff_options.interhunk_lines = 0;

	if ((error = git_diff_tree_to_workdir(
					&diff, blame->repository, tree, &diff_options)) < 0)
		goto on_error;

	wd_diff =  git_blame_workdir_diff__alloc();
	if (!wd_diff)
		goto on_error;

	if ((error = git_diff_foreach(
					diff, NULL, NULL, process_workdir_diff_hunk, NULL, wd_diff)) < 0)
		goto on_error;

	if ((error = merge_blame_workdir_diff(blame, wd_diff)) < 0)
		goto on_error;

	if ((error = git_blob_create_fromworkdir(
					&oid, blame->repository, blame->path)) < 0)
		goto on_error;
	if ((error = git_blob_lookup(&blame->final_blob, blame->repository, &oid))
			< 0)
		goto on_error;
	blame->final_buf = git_blob_rawcontent(blame->final_blob);
	blame->final_buf_size = git_blob_rawsize(blame->final_blob);

	git_array_clear(blame->line_index);
	index_blob_lines(blame);

	error = 0;

on_error:
	git_blame_workdir_diff__free(wd_diff);
	git_diff_free(diff);
	free(diff_file_paths.strings);
	git_tree_free(tree);
	git_object_free(obj);

	return error;
}

/*******************************************************************************
 * File blaming
 ******************************************************************************/

int git_blame_file(
		git_blame **out,
		git_repository *repo,
		const char *path,
		git_blame_options *options)
{
	int error = -1;
	git_blame_options normOptions = GIT_BLAME_OPTIONS_INIT;
	git_blame *blame = NULL;
	git_oid oid_head;
	git_reference_name_to_id(&oid_head, repo, "HEAD");

	assert(out && repo && path);
	if ((error = normalize_options(&normOptions, options, repo)) < 0)
		goto on_error;

	blame = git_blame__alloc(repo, normOptions, path);
	GIT_ERROR_CHECK_ALLOC(blame);

	if ((error = load_blob(blame)) < 0) {
		if (normOptions.flags & GIT_BLAME_INCLUDE_UNCOMMITTED_CHANGES) {
			if ((error = git_blame_new_file(blame)) < 0)
				goto on_error;
			*out = blame;
			return 0;
		} else {
			goto on_error;
		}
	}

	if ((error = blame_internal(blame)) < 0)
		goto on_error;

	if (normOptions.flags & GIT_BLAME_INCLUDE_UNCOMMITTED_CHANGES &&
			git_oid_equal(&oid_head, &normOptions.newest_commit)) {
		if ((error = update_blame_with_uncommitted_changes(blame)) < 0)
			goto on_error;
	}

	*out = blame;
	return 0;

on_error:
	git_blame_free(blame);
	return error;
}

/*******************************************************************************
 * Buffer blaming
 *******************************************************************************/

static bool hunk_is_bufferblame(git_blame_hunk *hunk)
{
	return git_oid_is_zero(&hunk->final_commit_id);
}

static int buffer_hunk_cb(
	const git_diff_delta *delta,
	const git_diff_hunk *hunk,
	void *payload)
{
	git_blame *blame = (git_blame*)payload;
	uint32_t wedge_line;

	GIT_UNUSED(delta);

	wedge_line = (hunk->old_lines == 0) ? hunk->new_start : hunk->old_start;
	blame->current_diff_line = wedge_line;

	blame->current_hunk = (git_blame_hunk*)git_blame_get_hunk_byline(blame, wedge_line);
	if (!blame->current_hunk) {
		/* Line added at the end of the file */
		blame->current_hunk = new_hunk(wedge_line, 0, wedge_line, blame->path);
		GIT_ERROR_CHECK_ALLOC(blame->current_hunk);

		git_vector_insert(&blame->hunks, blame->current_hunk);
	} else if (!hunk_starts_at_or_after_line(blame->current_hunk, wedge_line)){
		/* If this hunk doesn't start between existing hunks, split a hunk up so it does */
		blame->current_hunk = split_hunk_in_vector(&blame->hunks, blame->current_hunk,
				wedge_line - blame->current_hunk->orig_start_line_number, true);
		GIT_ERROR_CHECK_ALLOC(blame->current_hunk);
	}

	return 0;
}

static int ptrs_equal_cmp(const void *a, const void *b) { return a<b ? -1 : a>b ? 1 : 0; }
static int buffer_line_cb(
	const git_diff_delta *delta,
	const git_diff_hunk *hunk,
	const git_diff_line *line,
	void *payload)
{
	git_blame *blame = (git_blame*)payload;

	GIT_UNUSED(delta);
	GIT_UNUSED(hunk);
	GIT_UNUSED(line);

	if (line->origin == GIT_DIFF_LINE_ADDITION) {
		if (hunk_is_bufferblame(blame->current_hunk) &&
		    hunk_ends_at_or_before_line(blame->current_hunk, blame->current_diff_line)) {
			/* Append to the current buffer-blame hunk */
			blame->current_hunk->lines_in_hunk++;
			shift_hunks_by(&blame->hunks, blame->current_diff_line+1, 1);
		} else {
			/* Create a new buffer-blame hunk with this line */
			shift_hunks_by(&blame->hunks, blame->current_diff_line, 1);
			blame->current_hunk = new_hunk(blame->current_diff_line, 1, 0, blame->path);
			GIT_ERROR_CHECK_ALLOC(blame->current_hunk);

			git_vector_insert_sorted(&blame->hunks, blame->current_hunk, NULL);
		}
		blame->current_diff_line++;
	}

	if (line->origin == GIT_DIFF_LINE_DELETION) {
		/* Trim the line from the current hunk; remove it if it's now empty */
		size_t shift_base = blame->current_diff_line + blame->current_hunk->lines_in_hunk+1;

		if (--(blame->current_hunk->lines_in_hunk) == 0) {
			size_t i;
			shift_base--;
			if (!git_vector_search2(&i, &blame->hunks, ptrs_equal_cmp, blame->current_hunk)) {
				git_vector_remove(&blame->hunks, i);
				free_hunk(blame->current_hunk);
				blame->current_hunk = (git_blame_hunk*)git_blame_get_hunk_byindex(blame, (uint32_t)i);
			}
		}
		shift_hunks_by(&blame->hunks, shift_base, -1);
	}
	return 0;
}

int git_blame_buffer(
		git_blame **out,
		git_blame *reference,
		const char *buffer,
		size_t buffer_len)
{
	git_blame *blame;
	git_diff_options diffopts = GIT_DIFF_OPTIONS_INIT;
	size_t i;
	git_blame_hunk *hunk;

	diffopts.context_lines = 0;

	assert(out && reference && buffer && buffer_len);

	blame = git_blame__alloc(reference->repository, reference->options, reference->path);
	GIT_ERROR_CHECK_ALLOC(blame);

	/* Duplicate all of the hunk structures in the reference blame */
	git_vector_foreach(&reference->hunks, i, hunk) {
		git_blame_hunk *h = dup_hunk(hunk);
		GIT_ERROR_CHECK_ALLOC(h);

		git_vector_insert(&blame->hunks, h);
	}

	/* Diff to the reference blob */
	git_diff_blob_to_buffer(reference->final_blob, blame->path,
		buffer, buffer_len, blame->path, &diffopts,
		NULL, NULL, buffer_hunk_cb, buffer_line_cb, blame);

	*out = blame;
	return 0;
}

int git_blame_options_init(git_blame_options *opts, unsigned int version)
{
	GIT_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git_blame_options, GIT_BLAME_OPTIONS_INIT);
	return 0;
}

int git_blame_init_options(git_blame_options *opts, unsigned int version)
{
	return git_blame_options_init(opts, version);
}
