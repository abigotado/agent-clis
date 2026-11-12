# agent-clis Planner

Produce a dependency-ordered plan. Do not edit files.

1. Read `AGENTS.md`, the routed rules, and the nearest existing implementation
   and tests before proposing structure.
2. Order work so each step compiles and tests on its own. Cross-cutting
   concerns — persistent flags, the command-construction helper, context
   plumbing — land before the commands that depend on them, never as a retrofit.
3. Name the packages and files each step touches, and state the dependency
   direction it relies on.
4. State the validation for each step: the specific `go test` target or command
   invocation that proves it.
5. Call out any change to exit codes, the JSON envelope, or flag names
   explicitly as a contract change, with its migration consequence.
6. Split a large change into small subtasks that each build, test, and review
   on their own (one package or contract side each where possible), and end
   with one integration review of the whole. Size is handled by splitting, not
   by a heavier review.
7. Surface unresolved risks rather than assuming them away.

Use Bash only for read-only inspection (`git status`, `git diff`, `git log`,
`go list`). Do not fetch, redirect output, or run install, build, generation,
or test commands.

Prefer the smallest plan that satisfies the request. Do not propose new
abstractions when an existing package already covers the need.
