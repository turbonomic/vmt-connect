# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    = -v
SPHINXBUILD   = python -msphinx
SPHINXPROJ    = vmt-connect
SOURCEDIR     = source
BUILDDIR      = ../../vmt-connect-docs
LINKCHECKDIR  = source/_build/linkcheck
#PYTHONPATH    = ../

#export PYTHONPATH

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

clean:
	@echo "Clean disabled."

linkcheck:
	@sphinx-build -b linkcheck "$(SOURCEDIR)" "$(LINKCHECKDIR)" 

.PHONY: help Makefile clean

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
