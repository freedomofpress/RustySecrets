SHELL = bash

PROTOC := protoc

DEST_DIR := ../src/proto

BASE_PROTOS := $(wildcard *.proto)
BASE_RUSTS := $(addprefix $(DEST_DIR)/, $(BASE_PROTOS:.proto=.rs))

DSS_PROTOS := $(wildcard dss/*.proto)
DSS_RUSTS := $(addprefix $(DEST_DIR)/, $(DSS_PROTOS:.proto=.rs))

WRAPPED_PROTOS := $(wildcard wrapped/*.proto)
WRAPPED_RUSTS := $(addprefix $(DEST_DIR)/, $(WRAPPED_PROTOS:.proto=.rs))

OUT_DIR := _out

.PHONY: all base wrapped dss clean

all: base wrapped dss

base: $(BASE_RUSTS)

wrapped: $(WRAPPED_RUSTS)

dss: $(DSS_RUSTS)

$(DEST_DIR)/%.rs: %.proto
	@echo -n "Processing '$<'..."
	@$(RM) -r $(OUT_DIR)
	@mkdir -p $(OUT_DIR)
	@$(PROTOC) --rust_out $(OUT_DIR) $<
	@echo " Done."
	@echo -n "Moving generated file to '$(dir $@)'..."
	@mkdir -p $(dir $@)
	@mv $(OUT_DIR)/*.rs $(dir $@)
	@echo " Done."

clean:
	$(RM) $(BASE_RUSTS)
	$(RM) $(WRAPPED_RUSTS)
	$(RM) $(DSS_RUSTS)
