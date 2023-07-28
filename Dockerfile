FROM jlnftk/honeypot:latest 

WORKDIR honeypot
COPY code code

USER honeypot
CMD cd code/modules/ ; bash start_honeypot.sh
