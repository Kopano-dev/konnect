LOGINSCREEN_BG_SRC ?= kopano-augmenting-teamwork-2142x1080.png

LOGINSCREEN_BG_WIDTH            = $(shell identify -format '%w' loginscreen-bg.jpg)
LOGINSCREEN_BG_HEIGHT           = $(shell identify -format '%h' loginscreen-bg.jpg)
LOGINSCREEN_BG_THUMB_BASE64     = $(shell base64 -w0 loginscreen-bg-thumb.jpg)
LOGINSCREEN_BG_THUMB_BASE64_SVG = $(shell base64 -w0 loginscreen-bg-thumb.svg)

all: loginscreen-bg.css

.PHONY: loginscreen-bg.jpg
loginscreen-bg.jpg: $(LOGINSCREEN_BG_SRC)
	convert -strip -interlace Plane -gaussian-blur 0.05 -define jpeg:dct-method=float -quality 80% $< $@
	jpegoptim -v --all-progressive --strip-all -m75 $@

loginscreen-bg-thumb.jpg: loginscreen-bg.jpg
	convert -geometry x40 -strip -define jpeg:dct-method=float -quality 50% $< $@

loginscreen-bg-thumb.svg: loginscreen-bg-thumb.svg.in | loginscreen-bg-thumb.jpg loginscreen-bg.jpg
	WIDTH=$(LOGINSCREEN_BG_WIDTH) HEIGHT=$(LOGINSCREEN_BG_HEIGHT) \
		IMAGE_DATA=$(LOGINSCREEN_BG_THUMB_BASE64) \
		envsubst < $< > $@

loginscreen-bg.css: loginscreen-bg.css.in | loginscreen-bg-thumb.svg
	IMAGE_DATA=$(LOGINSCREEN_BG_THUMB_BASE64_SVG) \
		envsubst < $< > $@

clean:
	rm -f loginscreen-bg.jpg
	rm -f loginscreen-bg-thumb.jpg
	rm -f loginscreen-bg-thumb.svg
	rm -f loginscreen-bg.css
