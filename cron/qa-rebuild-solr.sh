
cd /src/ckan

ps auxww | grep "queue=qa-daily" | awk '{print $2}' | sudo xargs kill -9

# rebuild solr index
sudo -u www-data /home/co/ckan/bin/paster search-index rebuild --config=/var/ckan/ckan.ini

