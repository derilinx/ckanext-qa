import uuid
from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import types
from sqlalchemy.ext.declarative import declarative_base

import ckan.model as model

log = __import__('logging').getLogger(__name__)

Base = declarative_base()


def make_uuid():
    return unicode(uuid.uuid4())


class QA(Base):
    """
    Contains the latest results per dataset/resource for QA tasks
    run against them.
    """
    __tablename__ = 'qa'

    id = Column(types.UnicodeText, primary_key=True, default=make_uuid)
    package_id = Column(types.UnicodeText, nullable=False, index=True)
    resource_id = Column(types.UnicodeText, nullable=False, index=True)
    resource_timestamp = Column(types.DateTime)  # key to resource_revision
    archival_timestamp = Column(types.DateTime)

    openness_score = Column(types.Integer)
    openness_score_reason = Column(types.UnicodeText)
    format = Column(types.UnicodeText)

    created = Column(types.DateTime, default=datetime.now)
    updated = Column(types.DateTime)

    def __repr__(self):
        summary = 'score=%s format=%s' % (self.openness_score, self.format)
        details = self.openness_score_reason
        package = model.Package.get(self.package_id)
        package_name = package.name if package else '?%s?' % self.package_id
        return '<QA %s /dataset/%s/resource/%s %s>' % \
            (summary, package_name, self.resource_id, details)

    def as_dict(self):
        result = {}
        result['value'] = self.openness_score
        result['last_updated'] = self.created

        result['format'] = self.format
        result['archiver_status'] = self.archiver_status
        result['reason'] = self.openness_score_reason

        # deprecated keys
        result['openness_score'] = self.openness_score
        result['openness_score_reason'] = self.openness_score_reason
        result['openness_updated'] = self.created
        return result

    @classmethod
    def get_for_resource(cls, resource_id):
        return model.Session.query(cls).filter(cls.resource_id==resource_id).first()

    @classmethod
    def get_for_package(cls, package_id):
        '''Returns the QA for the given package. May not be any if the package
        has no resources or has not been archived. It checks the resources are
        not deleted.'''
        return model.Session.query(cls) \
                    .filter(cls.package_id==package_id) \
                    .join(model.Resource, cls.resource_id==model.Resource.id) \
                    .filter(model.Resource.state=='active') \
                    .all()

    @classmethod
    def create(cls, resource_id):
        c = cls()
        c.resource_id = resource_id

        # Find the package_id for the resource.
        q = """
            SELECT P.id from package P
            INNER JOIN resource_group RG ON RG.package_id = P.id
            INNER JOIN resource R ON R.resource_group_id = RG.id
            WHERE R.id = '%s';
        """
        row = model.Session.execute(q % c.resource_id).first()
        if not row or not row[0]:
            raise Exception("Missing dataset")
        c.package_id = row[0]
        return c

def aggregate_qa_for_a_dataset(qa_objs):
    '''Returns aggregated archival info for a dataset, given the archivals for
    its resources (returned by get_for_package).
    :param qa_objs: A list of the QA objects for a dataset's resources
    :type qa_objs: A list of QA objects
    :returns: QA dict about the dataset, with keys:
                openness_score
                openness_score_reason
    '''
    qa_dict = {'openness_score': None, 'openness_score_reason': None}
    for qa in qa_objs:
        # openness_score takes the highest i.e. optimistic
        # openness_score_reason matches the status_id
        if qa_dict['openness_score'] is None or \
                qa.openness_score > qa_dict['openness_score']:
            qa_dict['openness_score'] = qa.openness_score
            qa_dict['openness_score_reason'] = qa.openness_score_reason
    return qa_dict

def init_tables(engine):
    Base.metadata.create_all(engine)
    log.info('QA database tables are set-up')
