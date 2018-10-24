THEME  := styles/bright.css styles/ribbon.css
LIBCSS := styles/defaults.scss styles/fonts.scss styles/reset.scss

all: $(THEME)
	pandoc --template template.shower \
        -t revealjs slides.md -V theme=ribbon > slides.html

	./fix.py slides.html

%.css: %.scss $(LIBCSS)
	sass $< > $@
