FROM jlnftk/honeypot:latest 
COPY code code

USER honeypot
CMD cd honeypot/code/modules ; bash start_honeypot.sh
