import gitlab
import json
import os

gitlab_url = "http://dccscr.dsop.io"
gitlab_key = os.environ['GITLAB_KEY']


dccscr_project_id = 43

SAMPLE_IMAGE_NAME = "openjdk"
SAMPLE_IMAGE_VERSION = "1.8"


def main():
    proj = init(dccscr_project_id)
    get_all_the_things_json(proj, SAMPLE_IMAGE_NAME, SAMPLE_IMAGE_VERSION)


# working
def get_all_the_things_json(proj, im_name, im_ver):
    # ret = dict()

    first_call = get_whitelist_path_ref(proj, im_name, im_ver)

    if first_call:
        fn = first_call[0]
        ver = first_call[1]

        c = get_whitelist_file_contents(proj, fn, ver)
        f = []
        if c[3]:
            f = get_complete_whitelist_for_image(proj, im_name, im_ver)
            ret = {
                'image_name': im_name,
                'image_version': im_ver,
                'parent_name': c[3],
                'parent_version': c[4],
                'complete_whitelist': f[2],
                'delta_whitelist': c[2],
                'parents_whitelist': f[2]-set(c[2]),
                'report_s3': c[5]
            }
        else:
            ret = {
                'image_name': im_name,
                'image_version': im_ver,
                'parent_name': c[3],
                'parent_version': c[4],
                'complete_whitelist': c[2],
                'delta_whitelist': c[2],
                'parents_whitelist': [],
                'report_s3': c[5]
            }
        # print(json.dump(ret))
        app_json = json.dumps(ret, default=set_default)
        return str(app_json)
    else:
        return im_name, im_ver, "not found."


# working
def get_whitelist_file_contents(proj, item_path, item_ref):
    f = proj.files.get(file_path=item_path, ref=item_ref)
    try:
        j = json.loads(f.decode())
    except ValueError as error:
        print("JSON object issue: %s") % error
    return j['image_name'], j['image_tag'], \
           j['whitelisted_vulnerabilities'], \
           j['image_parent_name'], j['image_parent_tag'], \
           j['report_s3']


# working
def get_complete_whitelist_for_image(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)
    total_wl = set()

    for item in all_wls:
        contents = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        wl = contents[2]
        par_image = contents[3];
        par_tag = contents[4]
        report_s3 = contents[5]
        if contents[0] == im_name and contents[1] == im_tag:
            total_wl |= set(contents[2])
            if len(par_image) > 0 and len(par_tag) > 0:
                total_wl |= get_complete_whitelist_for_image(proj, par_image, par_tag)[2]
    return wl[0], wl[1], total_wl, wl[2]



def get_whitelist_path_ref(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)

    for item in all_wls:
        wl = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if wl[0] == im_name and wl[1] == im_tag:
            return item['filename'], item['ref']
    return False


# working
def does_image_exist(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)

    for item in all_wls:
        wl = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if wl[0] == im_name and wl[1] == im_tag:
            return True
    return False


# working
def get_whitelist_filenames(project):
    wl_fns = project.search('blobs', 'whitelisted_vulnerabilities')
    return wl_fns


def get_all_filename_and_refs_json(project):
    wl_fns = project.search('blobs', 'whitelisted_vulnerabilities')
    filename_list = list()
    for file in wl_fns:
        filename_list.append((file['filename'], file['ref']))
    return json.dumps(filename_list)


def init(pid):
    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
    gl.auth()
    return gl.projects.get(pid)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


if __name__ == "__main__":
    main()  # with if