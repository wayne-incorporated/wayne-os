# Feedback Scripts

These scripts produce data to be included in feedback reports.  They are often
run directly by debugd when it generates system reports.

Ideally scripts in here should not be here, but live alongside the projects that
make more sense.  For example, if a script runs a program or two, the project
that installs that program would be a better home.

Alternatively, if the script is very short (e.g., only runs a single program),
it could be inlined directly into debugd.

As a last resort, this project is used to hold scripts that don't have a better
home.
