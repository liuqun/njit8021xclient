#
local_source_files := eap_responser_main.c
local_object_files := $(local_source_files:.c=.o)
local_executable_file := eap_responser
local_executable_file := $(addsuffix $(EXEEXT), $(local_executable_file))
#-------------------------------------------------
$(local_executable_file): $(local_object_files)
	$(LINK.o) $^ -o $@
#-------------------------------------------------
executable_files += $(local_executable_file)
source_files += $(local_source_files)
object_files += $(local_object_files)

