import re, string, random
import MySQLdb as mdb
import os, json, yaml
from marshmallow import Schema, fields

# load config from yaml file
with open('/Users/cainelli/.mxh-consistency') as f:
  cfg = yaml.safe_load(f)

class DomainSchema(Schema):
  domain = fields.String(required=True)
  creation = fields.DateTime()
  server = fields.String(required=True)
  updated = fields.DateTime()
  cos = fields.String()
  allowed_ip_masks = fields.String()
  allowed_transport_agents = fields.String()
  address = fields.String(required=True)
  base = fields.String(required=True)
  directory_type = fields.String(required=True)
  next_update = fields.DateTime(required=True)
  override_flag = fields.String(required=True)
  user = fields.String(required=True)
  port = fields.String(required=True)
  total_users = fields.Integer()

class Domain(object):
  def __init__(self, mxhero):

    self.conn = mdb.connect(
    user = cfg['environment'][mxhero]['db_user'],
    passwd = cfg['environment'][mxhero]['db_pass'],
    db = cfg['environment'][mxhero]['db_name'],
    host = cfg['environment'][mxhero]['db_host'],
    port = cfg['environment'][mxhero]['db_port'],
    charset='utf8')
  
    self.cur = self.conn.cursor(mdb.cursors.DictCursor)


  def get(self, domain):
    query = "SELECT * FROM domain LEFT JOIN domain_adldap ON domain.domain = domain_adldap.domain WHERE domain.domain = '%s'" % domain
    self.cur.execute(query)

    result = self.cur.fetchone()
    query = "SELECT * FROM account_aliases WHERE domain_alias='%s'" % domain     
    self.cur.execute(query)
 
    res = self.cur.execute(query)
    result['total_users'] = int(res)
    if result:
      domain = DomainSchema(many=False).dump(result)

      return domain.data


  def delete(self, domain):

    if not self.exists(domain):
      return {'message' : 'domain do not exist: %s' % domain}, 204

    r = self.get(domain)
    if r['total_users'] > 1:
      return {'message' : 'Make sure you deleted all accounts before delete the domain'}, 400

    logger.info('deleting domain %s' % domain)

    q = []
    # app users
    q.append("DELETE app_users_authorities FROM app_users_authorities INNER JOIN app_users ON app_users.id = app_users_authorities.app_users_id WHERE app_users.domain = %s")
    q.append("DELETE FROM app_users WHERE domain = %s")

    # misc
    q.append("DELETE FROM catchall WHERE domain_id = %s")
    q.append("DELETE FROM zimbra_provider_data WHERE domain = %s")

    # adsync
    q.append("DELETE FROM domain_adldap WHERE domain = %s")
    q.append("DELETE FROM domain_adldap_properties WHERE domain = %s")

    # emails
    q.append("DELETE FROM account_aliases WHERE domain_id = %s")
    q.append("DELETE FROM email_accounts WHERE domain_id = %s")
    q.append("DELETE FROM email_accounts_properties WHERE domain_id = %s")

    # group
    q.append("DELETE FROM groups WHERE domain_id = %s")

    # rules
    q.append("DELETE features_rules_directions FROM features_rules_directions INNER JOIN features_rules ON features_rules_directions.rule_id = features_rules.id WHERE features_rules.domain_id = %s")
    q.append("DELETE features_rules_properties FROM features_rules_properties INNER JOIN features_rules ON features_rules_properties.rule_id = features_rules.id WHERE features_rules.domain_id = %s")
    q.append("DELETE FROM features_rules WHERE domain_id = %s")

    # domain itself
    q.append("DELETE FROM domains_aliases WHERE domain = %s")
    q.append("DELETE FROM domain WHERE domain = %s")

    for query in q:
      self.cur.execute(query, (domain,))
    
    try:
      self.conn.commit()
    except Exception, e:
      err_message = 'could not execute query'
      logger.error(err_message % e)
      return {'message' : '%s' % err_message}, 501
    
    return {'message' : 'domain %s successfully deleted' % domain}, 200

  def create(self, domain, reqdata):
    """
    desc: create and configure mxhero domains

    param: domain(str): domain to create.
    param: reqdata(dict): dictionary with sets of domain configuration


    return {
      'message': "success message|error message"
      'username' : $console_username
      'password' : $console_password
    }, $HTTP CODE
    """

    if self.exists(domain):
      return {'message' : 'domain already exist: %s' % domain}, 200

    # create domain
    self.cur.execute("INSERT INTO domain(domain, creation, server, updated) VALUES (%s, NOW(), %s, NOW())", (domain, reqdata['inbound_server']))
    self.cur.execute("INSERT INTO domains_aliases(alias, created, domain) VALUES (%s, NOW(), %s)", (domain, domain))

    # create adsync
    adsync_base = domain.replace('.',',dc=')
    adsync_base = 'dc=%s' % adsync_base

    self.cur.execute("INSERT INTO domain_adldap(domain, address, base, override_flag, password, port, user, directory_type, next_update) VALUES(%s, %s, %s, 1, %s, %s, %s, %s, NOW() + INTERVAL 1 MINUTE)",
                      (domain, reqdata['adsync_host'], adsync_base, reqdata['adsync_pass'], reqdata['adsync_port'], reqdata['adsync_user'], reqdata['directory_type']))
    

    # create admin user
    admin_pass = self.random_pass()

    self.cur.execute("INSERT INTO app_users(creation, enabled, last_name, locale, name, notify_email, password, user_name, domain) \
                      VALUES (NOW(), 1, %s, 'pt_BR', %s, %s, MD5(%s), %s, %s)",
                      (domain, reqdata['admin_email'], domain, admin_pass, domain, domain))

    app_user_id = self.cur.lastrowid
    self.cur.execute("INSERT INTO app_users_authorities (app_users_id, authorities_id) \
                      VALUES (%s, (SELECT id FROM authorities WHERE authority = 'ROLE_DOMAIN_ADMIN'))",
                      (app_user_id,))
    


    if reqdata['default_rules']:
      self.add_default_rules(domain)
      

    self.conn.commit()
    return {'message': 'domain successfully created', 'username' : domain, 'password': admin_pass}, 201


  def add_default_rules(self, domain):
    # ANTISPAM RULE
    self.cur.execute("INSERT INTO features_rules (two_ways, created, enabled, label, updated, domain_id, feature_id) \
                      VALUES ('', NOW(), 1, 'Antispam', NOW(), %s, (SELECT id FROM features WHERE component = 'org.mxhero.feature.externalantispam'))",
                      (domain,))
    rule_id = self.cur.lastrowid

    # anti-spam properties
    self.cur.execute("INSERT INTO features_rules_properties (property_key, property_value, rule_id) \
                      VALUES ('header.key', 'X-CMAE-Score', %s), ('header.value', '(?i)\\s*100.*', %s), \
                             ('header.managed', 'true', %s), ('header.id', '2', %s), \
                             ('action.selection', 'receive', %s), ('prefix.value', '[SPAM]', %s), \
                             ('add.header.key', 'X-Spam-Flag', %s) ,('add.header.value', 'YES', %s)",
                             (rule_id, rule_id, rule_id, rule_id, rule_id, rule_id, rule_id, rule_id))
    # anti-spam directions
    self.cur.execute("INSERT INTO features_rules_directions (directiom_type, free_value, rule_id) VALUES ('anyone', 'anyone', %s)",
                    (rule_id,))
    from_direction_id = self.cur.lastrowid


    self.cur.execute("INSERT INTO features_rules_directions (directiom_type, domain, free_value, rule_id) VALUES ('domain', %s, %s, %s)",
                    (domain, domain, rule_id))
    to_direction_id = self.cur.lastrowid

    self.cur.execute("UPDATE features_rules SET from_direction_id=%s, to_direction_id=%s WHERE id = %s",
                    (from_direction_id, to_direction_id, rule_id))


    # HERO ATTACH RULE
    self.cur.execute("INSERT INTO features_rules (created, enabled, label, updated, domain_id, feature_id) \
                      VALUES (NOW(), 1, 'Hero Attach', NOW(), %s, (SELECT id FROM features WHERE component = 'org.mxhero.feature.attachmentlink'))",
                      (domain,))
    rule_id = self.cur.lastrowid

    # hero attach properties
    self.cur.execute("INSERT INTO features_rules_properties (property_key, property_value, rule_id) \
                      VALUES ('max.size', '10', %s), ('action.selection', 'return', %s), \
                             ('return.message', 'O arquivo \${file-name} foi accessado por \${mxrecipient}.', %s),\
                             ('locale', 'pt_BR', %s)",
                             (rule_id, rule_id, rule_id, rule_id))

    # hero attach properties
    self.cur.execute("INSERT INTO features_rules_directions (directiom_type, domain, free_value, rule_id) \
                      VALUES ('domain', %s, %s, %s)", (domain, domain, rule_id))
    from_direction_id = self.cur.lastrowid

    self.cur.execute("INSERT INTO features_rules_directions (directiom_type, free_value, rule_id) \
                      VALUES ('anyone', 'anyone', %s)", (rule_id,))
    to_direction_id = self.cur.lastrowid


    self.cur.execute("UPDATE features_rules SET from_direction_id=%s, to_direction_id=%s WHERE id = %s",
                    (from_direction_id, to_direction_id, rule_id))


  def random_pass(self, size=6, chars=string.ascii_uppercase + string.digits + string.letters):
    return ''.join(random.choice(chars) for _ in range(size))

  def exists(self, domain):
    """
    desc: check if a domain exists.
    param domain:str:required - domain name.
    
    return: boolean.
    """
    query = "SELECT * FROM domains_aliases WHERE alias = '%s'" % domain

    self.cur.execute(query)
    if self.cur.rowcount:
      return True

    return False

  def is_direction_consistent(self, domain=''):

    query = "SELECT * FROM features_rules"
    if domain:
      query = "SELECT * FROM features_rules WHERE domain_id = '%s'" % domain

    self.cur.execute(query)
    res = self.cur.fetchall()

    for rule in res:
      print 'checking domain:[%s] rule:[%s]' % (rule['domain_id'], rule['id'])
      # print 'label:[%s]' % rule['label']
      query = "SELECT * FROM features_rules_directions WHERE rule_id = %s" % rule['id']
      self.cur.execute(query)
      res_directions = self.cur.fetchall()
 
      for direction in res_directions:
        if rule['from_direction_id'] != direction['id'] and rule['to_direction_id'] != direction['id']:
          print 'from:[%s] to:[%s] direction[%s]' % (rule['from_direction_id'], rule['to_direction_id'],direction['id'])
          
  def is_rule_consistent(self, domain=''):

    query = "SELECT * FROM features_rules_rules"
    if domain:
      query = "SELECT * FROM features_rules WHERE domain_id = '%s'" % domain

    self.cur.execute(query)
    res = self.cur.fetchall()

    for rule in res:
      print 'checking domain:[%s] rule:[%s]' % (rule['domain_id'], rule['id'])
      # print 'label:[%s]' % rule['label']
      query = "SELECT * FROM features_rules_directions WHERE rule_id = %s" % rule['id']
      self.cur.execute(query)
      res_directions = self.cur.fetchall()
 
      for direction in res_directions:
        if rule['from_direction_id'] != direction['id'] and rule['to_direction_id'] != direction['id']:
          print 'from:[%s] to:[%s] direction[%s]' % (rule['from_direction_id'], rule['to_direction_id'],direction['id'])
             
if __name__ == '__main__':
  mxh = Domain(mxhero='mxcorp')
  res = mxh.is_direction_consistent()
  res = mxh.is_rule_consistent()
  # print json.dumps(res, indent=2)