import logging
import os

import ckan.model as model
import ckan.plugins as p
from ckan.lib.celery_app import celery
from ckan.model.types import make_uuid

from ckanext.archiver.interfaces import IPipe
from ckanext.report.interfaces import IReport


log = logging.getLogger(__name__)


class QAPlugin(p.SingletonPlugin):
    p.implements(p.IConfigurer, inherit=True)
    p.implements(p.IRoutes, inherit=True)
    p.implements(IPipe, inherit=True)
    p.implements(p.IActions)
    p.implements(p.IAuthFunctions)
    p.implements(IReport)

    # IConfigurer

    def update_config(self, config):
        p.toolkit.add_template_directory(config, 'templates')
        # Update config gets called before the IRoutes methods
        self.root_dir = config.get('ckanext.qa.url_root', '') # deprecated

    # IRoutes

    def before_map(self, map):
        # Redirect from some old URLs
        map.redirect('%s/qa' % self.root_dir,
                     '/data/report')
        map.redirect('%s/qa/dataset/{a:.*}' % self.root_dir,
                     '/data/report')
        map.redirect('%s/qa/organisation/{a:.*}' % self.root_dir,
                     '/data/report')
        map.redirect('/api/2/util/qa/{a:.*}',
                     '/data/report')
        map.redirect('%s/qa/organisation/broken_resource_links' % self.root_dir,
                     '/data/report/broken-links')
        map.redirect('%s/qa/organisation/broken_resource_links/:organization' % self.root_dir,
                     '/data/report/broken-links/:organization')
        map.redirect('%s/qa/organisation/scores' % self.root_dir,
                     '/data/report/openness')
        map.redirect('%s/qa/organisation/scores/:organization' % self.root_dir,
                     '/data/report/openness/:organization')

        # Link checker
        res = 'ckanext.qa.controllers.qa_resource:QAResourceController'
        map.connect('qa_resource_checklink', '/qa/link_checker',
                    conditions=dict(method=['GET']),
                    controller=res,
                    action='check_link')

        return map

    # IPipe

    def receive_data(self, operation, queue, **params):
        '''Receive notification from ckan-archiver that a package has been updated.'''
        if operation == 'package-updated':
            package_id = params['package_id']

            package = model.Package.get(package_id)
            assert package

            create_qa_update_package_task(package, queue=queue)

    # IActions

    def get_actions(self):
        from ckanext.qa import logic_action as logic
        return {
            'search_index_update': logic.search_index_update,
            'qa_resource_show': logic.qa_resource_show,
            'qa_package_broken_show': logic.qa_package_broken_show,
            'qa_package_openness_show': logic.qa_package_openness_show,
            }

    # IAuthFunctions

    def get_auth_functions(self):
        from ckanext.qa import logic_auth as logic
        return {
            'search_index_update': logic.search_index_update,
            'qa_resource_show': logic.qa_resource_show,
            'qa_package_broken_show': logic.qa_package_broken_show,
            'qa_package_openness_show': logic.qa_package_openness_show,
            }

    # IReport

    def register_reports(self):
        """Register details of an extension's reports"""
        from ckanext.qa import reports
        return [reports.openness_report_info]


from pylons import config
ckan_ini_filepath = os.path.abspath(config.__file__)
def create_qa_update_package_task(package, queue):
    task_id = '%s-%s' % (package.name, make_uuid()[:4])
    celery.send_task('qa.update_package', args=[ckan_ini_filepath, package.id],
                     task_id=task_id, queue=queue)
    log.debug('QA of package put into celery queue %s: %s', queue, package.name)

from pylons import config
def create_qa_update_task(resource, queue):
    package = resource.resource_group.package
    task_id = '%s/%s/%s' % (package.name, resource.id[:4], make_uuid()[:4])
    ckan_ini_filepath = os.path.abspath(config.__file__)
    celery.send_task('qa.update', args=[ckan_ini_filepath, resource.id],
                     task_id=task_id, queue=queue)
    log.debug('QA of resource put into celery queue %s: %s/%s url=%r', queue, package.name, resource.id, resource.url)
