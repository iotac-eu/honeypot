FROM jlnftk/honeypot:latest 
USER honeypot
COPY code $HOME/honeypot/code
CMD cd $HOME/honeypot/code/modules ; bash start_honeypot.sh
