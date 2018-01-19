# Tools

CONVERT   ?= convert
IDENTIFY  ?= identify
BASE64    ?= base64
ENVSUBST  ?= envsubst
SCOUR     ?= scour

# Variables

LOGINSCREEN_BG_SRC ?= kopano-augmenting-teamwork-bg-7680.jpg
LOGINSCREEN_BG_OVERLAY_SRC ?= kopano-augmenting-teamwork-overlay.svg

LOGINSCREEN_BG_WIDTH            = $(shell $(IDENTIFY) -format '%w' loginscreen-bg.jpg)
LOGINSCREEN_BG_HEIGHT           = $(shell $(IDENTIFY) -format '%h' loginscreen-bg.jpg)
LOGINSCREEN_BG_THUMB_BASE64     = $(shell $(BASE64) -w0 loginscreen-bg-thumb.jpg)
LOGINSCREEN_BG_THUMB_BASE64_SVG = $(shell $(BASE64) -w0 loginscreen-bg-thumb.svg)

all: loginscreen-bg.css

loginscreen-bg.jpg: $(LOGINSCREEN_BG_SRC)
	$(CONVERT) -geometry x1080 -strip -interlace Plane -gaussian-blur 0.05 -define jpeg:dct-method=float -quality 75% $< $@

loginscreen-bg-thumb.jpg: loginscreen-bg.jpg
	$(CONVERT) -geometry x40 -strip -define jpeg:dct-method=float -quality 50% $< $@

loginscreen-bg-thumb.svg: loginscreen-bg-thumb.svg.in | loginscreen-bg-thumb.jpg loginscreen-bg.jpg
	WIDTH=$(LOGINSCREEN_BG_WIDTH) HEIGHT=$(LOGINSCREEN_BG_HEIGHT) \
		IMAGE_DATA=$(LOGINSCREEN_BG_THUMB_BASE64) \
		$(ENVSUBST) < $< > $@

loginscreen-bg-overlay.svg: $(LOGINSCREEN_BG_OVERLAY_SRC)
	$(SCOUR) --enable-viewboxing --create-groups --shorten-ids --enable-id-stripping \
		--enable-comment-stripping --disable-embed-rasters --remove-metadata --strip-xml-prolog -p 9 \
		-i $< -o $@

loginscreen-bg.css: loginscreen-bg.css.in | loginscreen-bg.jpg loginscreen-bg-thumb.svg loginscreen-bg-overlay.svg
	IMAGE_DATA=$(LOGINSCREEN_BG_THUMB_BASE64_SVG) \
		$(ENVSUBST) < $< > $@

clean:
	rm -f loginscreen-bg.jpg
	rm -f loginscreen-bg-thumb.jpg
	rm -f loginscreen-bg-thumb.svg
	rm -f loginscreen-bg.css
	rm -f loginscreen-bg-overlay.svg
