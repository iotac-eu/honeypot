FROM jlnftk/honeypot:latest 
COPY code code

USER honeypot
CMD cd code/modules/ ; bash start_honeypot.sh
