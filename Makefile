#
# Copyright (c) 2012 Trent Mick
# Copyright (c) 2015 Vartan Simonian
#
# node-adauth Makefile
#

#---- Files

JSSTYLE_FILES := $(shell find lib -name *.js)



#---- Targets

all:

.PHONY: check-jsstyle
check-jsstyle: $(JSSTYLE_FILES)
	./tools/jsstyle -o indent=2,doxygen,unparenthesized-return=0,blank-after-start-comment=0 $(JSSTYLE_FILES)

.PHONY: check
check: check-jsstyle
	@echo "Check ok."