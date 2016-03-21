
cd /src/ckan

ps auxww | grep "queue=qa-daily" | awk '{print $2}' | sudo xargs kill -9

# clear the queue
sudo -u www-data /home/co/ckan/bin/paster --plugin=ckanext-archiver celeryd clean --queue=qa-daily --config=/var/ckan/ckan.ini

# add to queue first batch of datasets
sudo -u www-data /home/co/ckan/bin/paster --plugin=ckanext-qa qa update first --queue=qa-daily --config=/var/ckan/ckan.ini
sudo -u www-data /home/co/ckan/bin/paster --plugin=ckanext-archiver celeryd run --queue=qa-daily --config=/var/ckan/ckan.ini 
