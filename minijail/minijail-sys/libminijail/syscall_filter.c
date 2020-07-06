/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "syscall_filter.h"

#include "util.h"

/* clang-format off */
#define ONE_INSTR	1
#define TWO_INSTRS	2

#define compiler_warn(_state, _msg, ...)                                       \
	warn("%s: %s(%zd): " _msg, __func__, (_state)->filename,               \
	     (_state)->line_number, ## __VA_ARGS__)

#define compiler_pwarn(_state, _msg, ...)                                      \
	compiler_warn(_state, _msg ": %m", ## __VA_ARGS__)
/* clang-format on */

int seccomp_can_softfail(void)
{
#if defined(USE_SECCOMP_SOFTFAIL)
	return 1;
#endif
	return 0;
}

int str_to_op(const char *op_str)
{
	if (!strcmp(op_str, "==")) {
		return EQ;
	} else if (!strcmp(op_str, "!=")) {
		return NE;
	} else if (!strcmp(op_str, "<")) {
		return LT;
	} else if (!strcmp(op_str, "<=")) {
		return LE;
	} else if (!strcmp(op_str, ">")) {
		return GT;
	} else if (!strcmp(op_str, ">=")) {
		return GE;
	} else if (!strcmp(op_str, "&")) {
		return SET;
	} else if (!strcmp(op_str, "in")) {
		return IN;
	} else {
		return 0;
	}
}

struct sock_filter *new_instr_buf(size_t count)
{
	struct sock_filter *buf = calloc(count, sizeof(struct sock_filter));
	if (!buf)
		die("could not allocate BPF instruction buffer");

	return buf;
}

struct filter_block *new_filter_block(void)
{
	struct filter_block *block = calloc(1, sizeof(struct filter_block));
	if (!block)
		die("could not allocate BPF filter block");

	block->instrs = NULL;
	block->last = block->next = NULL;

	return block;
}

void append_filter_block(struct filter_block *head, struct sock_filter *instrs,
			 size_t len)
{
	struct filter_block *new_last;

	/*
	 * If |head| has no filter assigned yet,
	 * we don't create a new node.
	 */
	if (head->instrs == NULL) {
		new_last = head;
	} else {
		new_last = new_filter_block();
		if (head->next != NULL) {
			head->last->next = new_last;
			head->last = new_last;
		} else {
			head->last = head->next = new_last;
		}
		head->total_len += len;
	}

	new_last->instrs = instrs;
	new_last->total_len = new_last->len = len;
	new_last->last = new_last->next = NULL;
}

void extend_filter_block_list(struct filter_block *list,
			      struct filter_block *another)
{
	if (list->last != NULL) {
		list->last->next = another;
		list->last = another->last;
	} else {
		list->next = another;
		list->last = another->last;
	}
	list->total_len += another->total_len;
}

void append_ret_kill(struct filter_block *head)
{
	struct sock_filter *filter = new_instr_buf(ONE_INSTR);
	set_bpf_ret_kill(filter);
	append_filter_block(head, filter, ONE_INSTR);
}

void append_ret_trap(struct filter_block *head)
{
	struct sock_filter *filter = new_instr_buf(ONE_INSTR);
	set_bpf_ret_trap(filter);
	append_filter_block(head, filter, ONE_INSTR);
}

void append_ret_errno(struct filter_block *head, int errno_val)
{
	struct sock_filter *filter = new_instr_buf(ONE_INSTR);
	set_bpf_ret_errno(filter, errno_val);
	append_filter_block(head, filter, ONE_INSTR);
}

void append_allow_syscall(struct filter_block *head, int nr)
{
	struct sock_filter *filter = new_instr_buf(ALLOW_SYSCALL_LEN);
	size_t len = bpf_allow_syscall(filter, nr);
	if (len != ALLOW_SYSCALL_LEN)
		die("error building syscall number comparison");

	append_filter_block(head, filter, len);
}

void allow_logging_syscalls(struct filter_block *head)
{
	unsigned int i;
	for (i = 0; i < log_syscalls_len; i++) {
		warn("allowing syscall: %s", log_syscalls[i]);
		append_allow_syscall(head, lookup_syscall(log_syscalls[i]));
	}
}

unsigned int get_label_id(struct bpf_labels *labels, const char *label_str)
{
	int label_id = bpf_label_id(labels, label_str);
	if (label_id < 0)
		die("could not allocate BPF label string");
	return label_id;
}

unsigned int group_end_lbl(struct bpf_labels *labels, int nr, int idx)
{
	char lbl_str[MAX_BPF_LABEL_LEN];
	snprintf(lbl_str, MAX_BPF_LABEL_LEN, "%d_%d_end", nr, idx);
	return get_label_id(labels, lbl_str);
}

unsigned int success_lbl(struct bpf_labels *labels, int nr)
{
	char lbl_str[MAX_BPF_LABEL_LEN];
	snprintf(lbl_str, MAX_BPF_LABEL_LEN, "%d_success", nr);
	return get_label_id(labels, lbl_str);
}

int is_implicit_relative_path(const char *filename)
{
	return filename[0] != '/' && (filename[0] != '.' || filename[1] != '/');
}

int compile_atom(struct parser_state *state, struct filter_block *head,
		 char *atom, struct bpf_labels *labels, int nr, int grp_idx)
{
	/* Splits the atom. */
	char *atom_ptr = NULL;
	char *argidx_str = strtok_r(atom, " ", &atom_ptr);
	if (argidx_str == NULL) {
		compiler_warn(state, "empty atom");
		return -1;
	}

	char *operator_str = strtok_r(NULL, " ", &atom_ptr);
	if (operator_str == NULL) {
		compiler_warn(state, "invalid atom '%s'", argidx_str);
		return -1;
	}

	char *constant_str = strtok_r(NULL, " ", &atom_ptr);
	if (constant_str == NULL) {
		compiler_warn(state, "invalid atom '%s %s'", argidx_str,
			      operator_str);
		return -1;
	}

	/* Checks that there are no extra tokens. */
	const char *extra = strtok_r(NULL, " ", &atom_ptr);
	if (extra != NULL) {
		compiler_warn(state, "extra token '%s'", extra);
		return -1;
	}

	if (strncmp(argidx_str, "arg", 3)) {
		compiler_warn(state, "invalid argument token '%s'", argidx_str);
		return -1;
	}

	char *argidx_ptr;
	long int argidx = strtol(argidx_str + 3, &argidx_ptr, 10);
	/*
	 * Checks that an actual argument index was parsed,
	 * and that there was nothing left after the index.
	 */
	if (argidx_ptr == argidx_str + 3 || *argidx_ptr != '\0') {
		compiler_warn(state, "invalid argument index '%s'",
			      argidx_str + 3);
		return -1;
	}

	int op = str_to_op(operator_str);
	if (op < MIN_OPERATOR) {
		compiler_warn(state, "invalid operator '%s'", operator_str);
		return -1;
	}

	char *constant_str_ptr;
	long int c = parse_constant(constant_str, &constant_str_ptr);
	if (constant_str_ptr == constant_str) {
		compiler_warn(state, "invalid constant '%s'", constant_str);
		return -1;
	}

	/*
	 * Looks up the label for the end of the AND statement
	 * this atom belongs to.
	 */
	unsigned int id = group_end_lbl(labels, nr, grp_idx);

	/*
	 * Builds a BPF comparison between a syscall argument
	 * and a constant.
	 * The comparison lives inside an AND statement.
	 * If the comparison succeeds, we continue
	 * to the next comparison.
	 * If this comparison fails, the whole AND statement
	 * will fail, so we jump to the end of this AND statement.
	 */
	struct sock_filter *comp_block;
	size_t len = bpf_arg_comp(&comp_block, op, argidx, c, id);
	if (len == 0)
		return -1;

	append_filter_block(head, comp_block, len);
	return 0;
}

int compile_errno(struct parser_state *state, struct filter_block *head,
		  char *ret_errno, int use_ret_trap)
{
	char *errno_ptr = NULL;

	/* Splits the 'return' keyword and the actual errno value. */
	char *ret_str = strtok_r(ret_errno, " ", &errno_ptr);
	if (!ret_str || strncmp(ret_str, "return", strlen("return")))
		return -1;

	char *errno_val_str = strtok_r(NULL, " ", &errno_ptr);

	if (errno_val_str) {
		char *errno_val_ptr;
		int errno_val = parse_constant(errno_val_str, &errno_val_ptr);
		/* Checks to see if we parsed an actual errno. */
		if (errno_val_ptr == errno_val_str || errno_val == -1) {
			compiler_warn(state, "invalid errno value '%s'",
				      errno_val_ptr);
			return -1;
		}

		append_ret_errno(head, errno_val);
	} else {
		if (!use_ret_trap)
			append_ret_kill(head);
		else
			append_ret_trap(head);
	}
	return 0;
}

struct filter_block *compile_policy_line(struct parser_state *state, int nr,
					 const char *policy_line,
					 unsigned int entry_lbl_id,
					 struct bpf_labels *labels,
					 int use_ret_trap)
{
	/*
	 * |policy_line| should be an expression of the form:
	 * "arg0 == 3 && arg1 == 5 || arg0 == 0x8"
	 *
	 * This is, an expression in DNF (disjunctive normal form);
	 * a disjunction ('||') of one or more conjunctions ('&&')
	 * of one or more atoms.
	 *
	 * Atoms are of the form "arg{DNUM} {OP} {NUM}"
	 * where:
	 *   - DNUM is a decimal number.
	 *   - OP is an operator: ==, !=, & (flags set), or 'in' (inclusion).
	 *   - NUM is an octal, decimal, or hexadecimal number.
	 *
	 * When the syscall arguments make the expression true,
	 * the syscall is allowed. If not, the process is killed.
	 *
	 * To block a syscall without killing the process,
	 * |policy_line| can be of the form:
	 * "return <errno>"
	 *
	 * This "return {NUM}" policy line will block the syscall,
	 * make it return -1 and set |errno| to NUM.
	 *
	 * A regular policy line can also include a "return <errno>" clause,
	 * separated by a semicolon (';'):
	 * "arg0 == 3 && arg1 == 5 || arg0 == 0x8; return {NUM}"
	 *
	 * If the syscall arguments don't make the expression true,
	 * the syscall will be blocked as above instead of killing the process.
	 */

	size_t len = 0;
	int grp_idx = 0;

	/* Checks for empty policy lines. */
	if (strlen(policy_line) == 0) {
		compiler_warn(state, "empty policy line");
		return NULL;
	}

	/* We will modify |policy_line|, so let's make a copy. */
	char *line = strdup(policy_line);
	if (!line)
		return NULL;

	/*
	 * We build the filter section as a collection of smaller
	 * "filter blocks" linked together in a singly-linked list.
	 */
	struct filter_block *head = new_filter_block();

	/*
	 * Filter sections begin with a label where the main filter
	 * will jump after checking the syscall number.
	 */
	struct sock_filter *entry_label = new_instr_buf(ONE_INSTR);
	set_bpf_lbl(entry_label, entry_lbl_id);
	append_filter_block(head, entry_label, ONE_INSTR);

	/* Checks whether we're unconditionally blocking this syscall. */
	if (strncmp(line, "return", strlen("return")) == 0) {
		if (compile_errno(state, head, line, use_ret_trap) < 0) {
			free_block_list(head);
			free(line);
			return NULL;
		}
		free(line);
		return head;
	}

	/* Splits the optional "return <errno>" part. */
	char *line_ptr;
	char *arg_filter = strtok_r(line, ";", &line_ptr);
	char *ret_errno = strtok_r(NULL, ";", &line_ptr);

	/*
	 * Splits the policy line by '||' into conjunctions and each conjunction
	 * by '&&' into atoms.
	 */
	char *arg_filter_str = arg_filter;
	char *group;
	while ((group = tokenize(&arg_filter_str, "||")) != NULL) {
		char *group_str = group;
		char *comp;
		while ((comp = tokenize(&group_str, "&&")) != NULL) {
			/* Compiles each atom into a BPF block. */
			if (compile_atom(state, head, comp, labels, nr,
					 grp_idx) < 0) {
				free_block_list(head);
				free(line);
				return NULL;
			}
		}
		/*
		 * If the AND statement succeeds, we're done,
		 * so jump to SUCCESS line.
		 */
		unsigned int id = success_lbl(labels, nr);
		struct sock_filter *group_end_block = new_instr_buf(TWO_INSTRS);
		len = set_bpf_jump_lbl(group_end_block, id);
		/*
		 * The end of each AND statement falls after the
		 * jump to SUCCESS.
		 */
		id = group_end_lbl(labels, nr, grp_idx++);
		len += set_bpf_lbl(group_end_block + len, id);
		append_filter_block(head, group_end_block, len);
	}

	/*
	 * If no AND statements succeed, we end up here,
	 * because we never jumped to SUCCESS.
	 * If we have to return an errno, do it,
	 * otherwise just kill the task.
	 */
	if (ret_errno) {
		if (compile_errno(state, head, ret_errno, use_ret_trap) < 0) {
			free_block_list(head);
			free(line);
			return NULL;
		}
	} else {
		if (!use_ret_trap)
			append_ret_kill(head);
		else
			append_ret_trap(head);
	}

	/*
	 * Every time the filter succeeds we jump to a predefined SUCCESS
	 * label. Add that label and BPF RET_ALLOW code now.
	 */
	unsigned int id = success_lbl(labels, nr);
	struct sock_filter *success_block = new_instr_buf(TWO_INSTRS);
	len = set_bpf_lbl(success_block, id);
	len += set_bpf_ret_allow(success_block + len);
	append_filter_block(head, success_block, len);

	free(line);
	return head;
}

int parse_include_statement(struct parser_state *state, char *policy_line,
			    unsigned int include_level,
			    const char **ret_filename)
{
	if (strncmp("@include", policy_line, strlen("@include")) != 0) {
		compiler_warn(state, "invalid statement '%s'", policy_line);
		return -1;
	}

	if (policy_line[strlen("@include")] != ' ') {
		compiler_warn(state, "invalid include statement '%s'",
			      policy_line);
		return -1;
	}

	/*
	 * Disallow nested includes: only the initial policy file can have
	 * @include statements.
	 * Nested includes are not currently necessary and make the policy
	 * harder to understand.
	 */
	if (include_level > 0) {
		compiler_warn(state, "@include statement nested too deep");
		return -1;
	}

	char *statement = policy_line;
	/* Discard "@include" token. */
	(void)strsep(&statement, " ");

	/*
	 * compile_filter() below receives a FILE*, so it's not trivial to open
	 * included files relative to the initial policy filename.
	 * To avoid mistakes, force the included file path to be absolute
	 * (start with '/'), or to explicitly load the file relative to CWD by
	 * using './'.
	 */
	const char *filename = statement;
	if (is_implicit_relative_path(filename)) {
		compiler_warn(
		    state,
		    "implicit relative path '%s' not supported, use './%s'",
		    filename, filename);
		return -1;
	}

	*ret_filename = filename;
	return 0;
}

/*
 * This is like getline() but supports line wrapping with \.
 */
static ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream)
{
	ssize_t ret = getline(lineptr, n, stream);
	if (ret < 0)
		return ret;

	char *line = *lineptr;
	/* Eat the newline to make processing below easier. */
	if (ret > 0 && line[ret - 1] == '\n')
		line[--ret] = '\0';

	/* If the line doesn't end in a backslash, we're done. */
	if (ret <= 0 || line[ret - 1] != '\\')
		return ret;

	/* This line ends in a backslash. Get the nextline. */
	line[--ret] = '\0';
	size_t next_n = 0;
	char *next_line = NULL;
	ssize_t next_ret = getmultiline(&next_line, &next_n, stream);
	if (next_ret == -1) {
		free(next_line);
		/* We couldn't fully read the line, so return an error. */
		return -1;
	}

	/* Merge the lines. */
	*n = ret + next_ret + 2;
	line = realloc(line, *n);
	line[ret] = ' ';
	memcpy(&line[ret + 1], next_line, next_ret + 1);
	free(next_line);
	*lineptr = line;
	return ret;
}

int compile_file(const char *filename, FILE *policy_file,
		 struct filter_block *head, struct filter_block **arg_blocks,
		 struct bpf_labels *labels, int use_ret_trap, int allow_logging,
		 unsigned int include_level)
{
	/* clang-format off */
	struct parser_state state = {
		.filename = filename,
		.line_number = 0,
	};
	/* clang-format on */
	/*
	 * Loop through all the lines in the policy file.
	 * Build a jump table for the syscall number.
	 * If the policy line has an arg filter, build the arg filter
	 * as well.
	 * Chain the filter sections together and dump them into
	 * the final buffer at the end.
	 */
	char *line = NULL;
	size_t len = 0;
	int ret = 0;

	while (getmultiline(&line, &len, policy_file) != -1) {
		char *policy_line = line;
		policy_line = strip(policy_line);

		state.line_number++;

		/* Allow comments and empty lines. */
		if (*policy_line == '#' || *policy_line == '\0') {
			/* Reuse |line| in the next getline() call. */
			continue;
		}

		/* Allow @include statements. */
		if (*policy_line == '@') {
			const char *filename = NULL;
			if (parse_include_statement(&state, policy_line,
						    include_level,
						    &filename) != 0) {
				compiler_warn(
				    &state,
				    "failed to parse include statement");
				ret = -1;
				goto free_line;
			}

			FILE *included_file = fopen(filename, "re");
			if (included_file == NULL) {
				compiler_pwarn(&state, "fopen('%s') failed",
					       filename);
				ret = -1;
				goto free_line;
			}
			if (compile_file(filename, included_file, head,
					 arg_blocks, labels, use_ret_trap,
					 allow_logging,
					 include_level + 1) == -1) {
				compiler_warn(&state, "'@include %s' failed",
					      filename);
				fclose(included_file);
				ret = -1;
				goto free_line;
			}
			fclose(included_file);
			continue;
		}

		/*
		 * If it's not a comment, or an empty line, or an @include
		 * statement, treat |policy_line| as a regular policy line.
		 */
		char *syscall_name = strsep(&policy_line, ":");
		if (policy_line == NULL) {
			warn("compile_file: malformed policy line, missing "
			     "':'");
			ret = -1;
			goto free_line;
		}

		policy_line = strip(policy_line);
		if (*policy_line == '\0') {
			compiler_warn(&state, "empty policy line");
			ret = -1;
			goto free_line;
		}

		syscall_name = strip(syscall_name);
		int nr = lookup_syscall(syscall_name);
		if (nr < 0) {
			compiler_warn(&state, "nonexistent syscall '%s'",
				      syscall_name);
			if (allow_logging) {
				/*
				 * If we're logging failures, assume we're in a
				 * debugging case and continue.
				 * This is not super risky because an invalid
				 * syscall name is likely caused by a typo or by
				 * leftover lines from a different architecture.
				 * In either case, not including a policy line
				 * is equivalent to killing the process if the
				 * syscall is made, so there's no added attack
				 * surface.
				 */
				/* Reuse |line| in the next getline() call. */
				continue;
			}
			ret = -1;
			goto free_line;
		}

		/*
		 * For each syscall, add either a simple ALLOW,
		 * or an arg filter block.
		 */
		if (strcmp(policy_line, "1") == 0) {
			/* Add simple ALLOW. */
			append_allow_syscall(head, nr);
		} else {
			/*
			 * Create and jump to the label that will hold
			 * the arg filter block.
			 */
			unsigned int id = bpf_label_id(labels, syscall_name);
			struct sock_filter *nr_comp =
			    new_instr_buf(ALLOW_SYSCALL_LEN);
			bpf_allow_syscall_args(nr_comp, nr, id);
			append_filter_block(head, nr_comp, ALLOW_SYSCALL_LEN);

			/* Build the arg filter block. */
			struct filter_block *block = compile_policy_line(
			    &state, nr, policy_line, id, labels, use_ret_trap);

			if (!block) {
				if (*arg_blocks) {
					free_block_list(*arg_blocks);
					*arg_blocks = NULL;
				}
				ret = -1;
				goto free_line;
			}

			if (*arg_blocks) {
				extend_filter_block_list(*arg_blocks, block);
			} else {
				*arg_blocks = block;
			}
		}
		/* Reuse |line| in the next getline() call. */
	}
	/* getline(3) returned -1. This can mean EOF or the below errors. */
	if (errno == EINVAL || errno == ENOMEM) {
		if (*arg_blocks) {
			free_block_list(*arg_blocks);
			*arg_blocks = NULL;
		}
		ret = -1;
	}

free_line:
	free(line);
	return ret;
}

int compile_filter(const char *filename, FILE *initial_file,
		   struct sock_fprog *prog, int use_ret_trap, int allow_logging)
{
	int ret = 0;
	struct bpf_labels labels;
	labels.count = 0;

	if (!initial_file) {
		warn("compile_filter: |initial_file| is NULL");
		return -1;
	}

	struct filter_block *head = new_filter_block();
	struct filter_block *arg_blocks = NULL;

	/* Start filter by validating arch. */
	struct sock_filter *valid_arch = new_instr_buf(ARCH_VALIDATION_LEN);
	size_t len = bpf_validate_arch(valid_arch);
	append_filter_block(head, valid_arch, len);

	/* Load syscall number. */
	struct sock_filter *load_nr = new_instr_buf(ONE_INSTR);
	len = bpf_load_syscall_nr(load_nr);
	append_filter_block(head, load_nr, len);

	/* If logging failures, allow the necessary syscalls first. */
	if (allow_logging)
		allow_logging_syscalls(head);

	if (compile_file(filename, initial_file, head, &arg_blocks, &labels,
			 use_ret_trap, allow_logging,
			 0 /* include_level */) != 0) {
		warn("compile_filter: compile_file() failed");
		ret = -1;
		goto free_filter;
	}

	/*
	 * If none of the syscalls match, either fall through to KILL,
	 * or return TRAP.
	 */
	if (!use_ret_trap)
		append_ret_kill(head);
	else
		append_ret_trap(head);

	/* Allocate the final buffer, now that we know its size. */
	size_t final_filter_len =
	    head->total_len + (arg_blocks ? arg_blocks->total_len : 0);
	if (final_filter_len > BPF_MAXINSNS) {
		ret = -1;
		goto free_filter;
	}

	struct sock_filter *final_filter =
	    calloc(final_filter_len, sizeof(struct sock_filter));

	if (flatten_block_list(head, final_filter, 0, final_filter_len) < 0) {
		free(final_filter);
		ret = -1;
		goto free_filter;
	}

	if (flatten_block_list(arg_blocks, final_filter, head->total_len,
			       final_filter_len) < 0) {
		free(final_filter);
		ret = -1;
		goto free_filter;
	}

	if (bpf_resolve_jumps(&labels, final_filter, final_filter_len) < 0) {
		free(final_filter);
		ret = -1;
		goto free_filter;
	}

	prog->filter = final_filter;
	prog->len = final_filter_len;

free_filter:
	free_block_list(head);
	free_block_list(arg_blocks);
	free_label_strings(&labels);
	return ret;
}

int flatten_block_list(struct filter_block *head, struct sock_filter *filter,
		       size_t index, size_t cap)
{
	size_t _index = index;

	struct filter_block *curr;
	size_t i;

	for (curr = head; curr; curr = curr->next) {
		for (i = 0; i < curr->len; i++) {
			if (_index >= cap)
				return -1;
			filter[_index++] = curr->instrs[i];
		}
	}
	return 0;
}

void free_block_list(struct filter_block *head)
{
	struct filter_block *current, *prev;

	current = head;
	while (current) {
		free(current->instrs);
		prev = current;
		current = current->next;
		free(prev);
	}
}
