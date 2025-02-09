import oci
import os,glob
import sys, getopt
import zipfile
import time
import xml.etree.ElementTree as ET

def main(argv):
    try:
        options, args = getopt.getopt(argv, "h:c:e:l:p:",
                                      ["compartmentid =",
                                       "entityid =",
                                       "loggroupid =",
                                       "path ="])
        print('options: ', options)
        print('args: ', args)
    except:
        print("Error Message ")

    compartmentid = ''
    entityid = ''
    loggroupid = ''
    path = ''
    for name, value in options:
        if name in ['-c', '--compartmentid']:
            compartmentid = value
        elif name in ['-e', '--entityid']:
            entityid = value
        elif name in ['-l', '--loggroupid']:
            loggroupid = value
        elif name in ['-p', '--path']:
            path = value

    try:
        # get source names from the given path
        sourcenames = []
        if (not path):
            print ("Error: Source path is empty!")
            return
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        srcnames = getsourcenames(path)
        sourcenames = set(srcnames)

        print("######################### Source entity Associations Details ######################")
        print("compartment_id :: ", compartmentid)
        print("loggroup_id :: ", loggroupid)
        print("path :: ", path)
        print("sources :: ", sourcenames)
        print("entity_id :: ", entityid)

        # get oci obo token from env var settings and create signer from obo delegation token
        obo_token = os.environ.get("OCI_obo_token")
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=obo_token)
        # create LogAnalytics client using signer
        la_client = oci.log_analytics.LogAnalyticsClient(config={}, signer=signer)
        #Create Objectstorage client
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)

        namespace = object_storage_client.get_namespace().data
        print("Tenancy NameSpace :: ", namespace)

        # Before proceeding to add association(s), check if the entity is eligible
        # by looking at lifecycleState and lifecycleDetails
        maxRetries = 30
        while (maxRetries > 0):
            get_entity = la_client.get_log_analytics_entity(
                namespace_name=namespace,
                log_analytics_entity_id=entityid)
            lc_state = get_entity.data.lifecycle_state
            print("Entity State :: ", lc_state)
            if (lc_state == 'ACTIVE'):
                break
            else:
                print('Entity is still not ACTIVE. Current lifecycle state: ', lc_state)
            try:
                time.sleep(10)
            except Exception:
                continue

        items=[]
        for source in sourcenames:
            assoc = oci.log_analytics.models.UpsertLogAnalyticsAssociation(
                agent_id=get_entity.data.management_agent_id,
                source_name=source,
                entity_id=entityid,
                entity_name=get_entity.data.name,
                entity_type_name=get_entity.data.entity_type_internal_name,
                host=get_entity.data.hostname,
                log_group_id=loggroupid)
            items.append(assoc)

        assocs=oci.log_analytics.models.UpsertLogAnalyticsAssociationDetails(
            compartment_id=compartmentid,
            items=items)

        # Read assoc payload from json file
        upsert_associations_response = la_client.upsert_associations(
            namespace_name = namespace,
            upsert_log_analytics_association_details = assocs,
            is_from_republish = False)

        print(upsert_associations_response.headers)
    except Exception:
        print('Error in adding source-entity association')
        raise

def getsourcenames(filepath):
    archive_dir = filepath
    print("archive_dir :: ", archive_dir)

    source_names = []
    for archive in glob.glob(os.path.join(archive_dir, '*.zip')):
        print('archive ::', archive)
        #print('archive path ::', os.path.join(archive_dir, archive))
        with zipfile.ZipFile(archive, 'r') as z:
            for filename in z.namelist():
                print('filename ::', filename)
                if filename.lower().endswith('.xml'):
                    with z.open(filename, mode='r') as cfile:
                        tree = ET.parse(cfile)
                        root = tree.getroot()
                        print('root attributes:: ', root.attrib)

                        sources = root.findall('{http://www.oracle.com/DataCenter/LogAnalyticsStd}Source')
                        if (len(sources) == 0):
                            sources = root.findall('Source')

                        for src in sources:
                            sourcename = src.get('name')
                            print('src :',src.attrib)
                            print('src name:',sourcename)
                            if src not in source_names:
                                source_names.append(sourcename)
    return source_names

if __name__ == "__main__":
    main(sys.argv[1:])
