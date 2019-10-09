import gitlab
import json
import helpers
import os

gitlab_url = "https://dccscr.dsop.io"
gitlab_key = os.environ['GITLAB_KEY']

def main():
    print("git_helpers.py")


# working
def get_whitelist_file_contents(proj, item_path, item_ref):
    f = proj.files.get(file_path=item_path, ref=item_ref)
    try:
        contents = json.loads(f.decode())
    except ValueError as error:
        print("JSON object issue: %s") % error
    return contents


def get_complete_whitelist_for_image(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)
    total_wl = []

    for item in all_wls:
        contents = get_whitelist_file_contents(proj, item['filename'], item['ref'])

        par_image = contents['image_parent_name']
        par_tag = contents['image_parent_tag']

        if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
            for x in get_whitelist_for_image(proj, im_name, im_tag):
                x.set_whitelist_source(im_name)
                total_wl.append(x)

            if len(par_image) > 0 and len(par_tag) > 0:
                for y in get_complete_whitelist_for_image(proj, par_image, par_tag):
                    y.set_whitelist_source(par_image)
                    total_wl.append(y)

    return total_wl


# working
def get_whitelist_for_image(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)
    wl = []

    for item in all_wls:
        contents = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
            for v in contents['whitelisted_vulnerabilities']:
                tar = helpers.Vuln(v)
                wl.append(tar)
    return wl


def get_whitelist_path_ref(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)

    for item in all_wls:
        wl = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if wl['image_name'] == im_name and wl['image_tag'] == im_tag:
            return item['filename'], item['ref']
    return False


# working
def does_image_exist(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)

    for item in all_wls:
        wl = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if wl['image_name'] == im_name and wl['image_tag'] == im_tag:
            return True
    return False


def get_whitelist_filenames(project):
    wl_fns = project.search('blobs', 'authorized_approvers')
    return_list = []
    for wl_fn in wl_fns:
        if "greylist" in wl_fn['filename']:
            return_list.append(wl_fn)
    return return_list


def get_all_filename_and_refs_json(project):
    wl_fns = project.search('blobs', 'authorized_approvers')
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