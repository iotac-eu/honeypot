FROM jlnftk/honeypot:latest 
COPY code code

USER honeypot
CMD cd $HOME/honeypot/code/modules ; bash start_honeypot.sh
