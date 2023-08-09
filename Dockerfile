FROM jlnftk/honeypot:latest 
USER honeypot
COPY code code
CMD cd $HOME/code/modules ; bash start_honeypot.sh
