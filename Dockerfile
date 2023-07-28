FROM jlnftk/honeypot:latest 

WORKDIR honeypot
COPY code code

RUN cd code/modules/ 
CMD bash start_honeypot.sh
