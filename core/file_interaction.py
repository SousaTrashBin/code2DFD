import os
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from output_generators.logger import logger
import core.technology_switch as tech_sw
import tmp.tmp as tmp


count = 0
total_length = 0
done = False

query_cache = dict()
exception_counter_keyword = int()

repo_cache = dict()
exception_counter_repo = 0


def detection_comment(file_name, line):
    """Checks if provided line is a comment. Based on language of the file, so only works for the ones with specified comment-delimiters.
    """

    language = os.path.splitext(file_name)[1]
    return (language == ".js" and line.replace(" ", "")[:2] == "//") or (
            language == ".java" and line.replace(" ", "")[:2] == "//") or (
            language == ".yml" and line.replace(" ", "")[:1] == "#")


def detection_import(line):
    """Checks if provided line is an import statement.
    """

    return line.startswith("import")


def detection_config(file_name):
    """Checks if provided file is a config file.
    """

    return "config" in file_name.casefold()


def extract_import(line):
    """Extracts modules from import lines. E.g.: input "import matplotlib.figure;" -> output "figure".
    """

    return line.split(".")[-1][:-1]


def extract_variable(line, submodule):
    """Extracts a variable that is changed based on some module.
    """

    return line.split("=")[0].strip().split()[-1] if "=" in line else line.split(";")[0].strip().split()[-1]


IGNORED_DIRECTORIES = frozenset({
    ".git", ".github", ".venv", "node_modules", "__pycache__",
    "test", "tests", "target", "build",
})


def source_files():
    """Enumerate the supplied snapshot without platform-specific shell tools."""
    root = Path(tmp.tmp_config["Repository"]["local_path"])
    for directory, children, files in os.walk(root):
        children[:] = sorted(name for name in children if name not in IGNORED_DIRECTORIES)
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError("Source snapshot contains a symbolic link")
            yield path


def search_keywords(keywords):
    """Keep legacy per-file results, with explicit read failures and relative exclusions."""
    root = Path(tmp.tmp_config["Repository"]["local_path"])
    if isinstance(keywords, str):
        keywords = [keywords]
    results = {}
    for keyword in keywords:
        try:
            expression = re.compile(keyword)
        except re.error:
            expression = re.compile(re.escape(keyword))
        for path in source_files():
            if path.suffix == ".md":
                continue
            try:
                content = path.read_text(encoding="utf-8").splitlines(keepends=True)
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(content, 1):
                match = expression.search(line)
                if match:
                    results[len(results)] = {
                        "content": content, "name": path.name,
                        "path": path.relative_to(root).as_posix(),
                        "line_nr": str(number), "span": str(match.span()),
                    }
                    break
    return results


def pagList2lines(pagList) -> dict:
    """Converts paginated list into files as lines.
    """

    results = dict()
    for p in pagList:
        containing_files_URLs = extract_downloadURL(p)
        for file in containing_files_URLs.keys():
            f = containing_files_URLs[file]
            try:
                id_ = max(results.keys()) + 1
            except:
                id_ = 0
            results[id_] = dict()

            results[id_]["content"] = file_as_lines(f["path"])
            results[id_]["name"] = f["name"]
            results[id_]["path"] = f["path"]

        return results


def extract_downloadURL(files) -> dict:
    """Returns URL to pull files from a repo that contain provided keyword.
    """

    containing_files_URLs = dict()
    for f in files:
        try:
            id_ = max(containing_files_URLs.keys()) + 1
        except:
            id_ = 0
        containing_files_URLs[id_] = dict()

        containing_files_URLs[id_]["path"] = f.path
        containing_files_URLs[id_]["name"] = f.name
    return containing_files_URLs


def get_struct(repo):
    """Returns structure of the repo (folders and files) and prints it.
    """

    struct = []
    contents = repo.get_contents("")
    while contents:
        file_content = contents.pop(0)
        if file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
        else:
            struct.append(str(file_content)[18:-2])
    return struct


def file_as_lines(path):
    """Downloads and splits raw file into lines.
    """

    local_path = tmp.tmp_config.get("Repository", "local_path")
    local_path = os.path.join(local_path, path)

    with open(local_path, "r") as file:
        file_as_lines = file.readlines()
    return file_as_lines


def detect_microservice(file_path, dfd):
    """Finds microservice that a file belongs to.
    """

    microservices_set = tech_sw.get_microservices(dfd)
    microservices = [microservices_set[x]["name"] for x in microservices_set.keys()]

    file_path_parts = Path(file_path).parts
    count = 0
    part = 0
    found = False

    while part < len(file_path_parts) and not found:
        for m in microservices:
            if m == file_path_parts[part]:
                microservice = m
                count += 1
        if count > 0:
            found = True
        part += 1
    if count == 1:
        return microservice
    else:
        if tmp.tmp_config.getboolean("Analysis Settings", "headless", fallback=False):
            raise ValueError("Ambiguous service ownership in headless analysis")
        print("\tFound " + str(count) + " microservices for file " + str(file_path) +". \
        \n\tPlease choose microservice that the file belongs to: ")
        i = 1
        for m in microservices:
            print("\t[" + str(i) + "] " + str(m))
            i += 1
        return microservices[int(input("\n\t > ")) - 1]


def find_variable(parameter: str, file) -> str:
    """ Looks for passed ´parameter´ in passed ´file´ or other files.
    """

    if parameter == "":
        return parameter
    if parameter[0] == "\"" and parameter[-1] == "\"":      # already string as needed, return this
        return parameter.strip("\"")

    elif "." in parameter:               # means that it refers to some other file -> look for that file, then go through lines
        try:
            parameter_variable = parameter.split(".")[-1]
            parameter_class = parameter.split(".")[-2]
            files_containing_class = search_keywords("class " + str(parameter_class))
            correct_file = None
            variable = None
            for filec in files_containing_class.keys():
                fc = files_containing_class[filec]
                for linec in range(len(fc["content"])):
                    if "class" in fc["content"][linec] and parameter_class in fc["content"][linec]:
                        correct_file = fc["name"]
                        inside_class_definition = True
                        lines_class = len(fc["content"]) - linec
                        i = 0
                        while inside_class_definition and i < lines_class:
                            if "}" in fc["content"][i]:
                                inside_class_definition = False
                            i += 1
                            if parameter_variable in fc["content"][linec + i] and "=" in fc["content"][linec + i]:
                                variable = fc["content"][linec + i].split("=")[1].strip().strip(";").strip().strip("\"")
            logger.info(f"Found {variable} in file {correct_file}")
        except:
            logger.info(f"Could not find a definition for {parameter}")
            return None
    else:           # means that it's a variable in this file -> go through lines to find it
        if parameter[-2:-1] == "()":
            return parameter
        else:
            try:
                parameter_variable = parameter
                for line in range(len(file["content"])):
                    if parameter_variable in file["content"][line] and "=" in file["content"][line] and ("private" in file["content"][line] or "public" in file["content"][line] or "protected" in file["content"][line]):
                        variable = file["content"][line].split("=")[1].strip().strip(";").strip().strip("\"")
                name = file["name"]
                logger.info(f"Found {variable} in this file ({name})")
            except:
                logger.info(f"Could not find a definition for {parameter}")
                return None
    return variable


def find_instances(class_of_interest: str) -> set:
    """For the input class name, finds instantiations of it and returns set of names of these objects.
    Uses regular expression for it. In case of wrong findings, the regex needs to be adjusted.
    """

    instances = set()
    files = search_keywords(class_of_interest)

    regex = re.compile("^ *\t*(private|protected|public) (final )?" + class_of_interest + "(<.*>)? \w+ *;")        # last part means: 0 or 1 <> with something in it, then whitespace, then any legal variable character as often as wanted, then whitespace if wanted, then semicolon
    re.ASCII
    for file in files.keys():
        f = files[file]
        for line in range(len(f["content"])):
            match = re.search(regex, f["content"][line])
            if match:
                obj = f["content"][line].split(class_of_interest)[1].split(">")[-1].strip().strip(";").strip()
                instances.add(obj)

    return instances


def resolve_url(url, microservice, dfd):
    """Resolve literal local destinations exactly; never match host substrings."""
    if not isinstance(url, str) or any(token in url for token in ("$", "{", "}")):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    matches = []
    for service in tech_sw.get_microservices(dfd).values():
        name = service["name"]
        if host and name.removeprefix("pom_").casefold() == host.casefold():
            matches.append(name)
        elif host in ("localhost", "127.0.0.1", "::1") and port is not None:
            if any(tag[0] == "Port" and str(tag[1]) == str(port)
                   for tag in service.get("tagged_values", ())):
                matches.append(name)
    return matches[0] if len(set(matches)) == 1 else False


def check_dockerfile(build_path: str):
    """Checks if under the service's build-path there is a dockerfile. If yes, returns it.
    """
    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    # find docker-compose path, since build-path is relative to that
    raw_files = get_file_as_lines("docker-compose.yml")
    if len(raw_files) == 0:
        raw_files = get_file_as_lines("docker-compose.yaml")
    if len(raw_files) == 0:
        return
    docker_compose_path = raw_files[0]["path"]  # TODO this assumes there is exactly 1 relevant docker-compose
    docker_compose_dir = os.path.dirname(docker_compose_path)

    build_path = PurePosixPath(build_path.strip("-'"))  # Build path is always posix, so resolve it accordingly
    build_path = os.path.normpath(build_path)

    docker_path = os.path.join(local_repo_path, os.path.join(docker_compose_dir, build_path))

    lines = list()

    dirs = list()

    if os.path.exists(docker_path):
        dirs.append(os.scandir(docker_path))
        while dirs:
            d = dirs.pop()
            for entry in d:
                if entry.is_file():
                    if entry.name.casefold() == "dockerfile":
                        with open(entry.path, "r") as file:
                            lines = file.readlines()
                elif entry.is_dir():
                    dirs.append(os.scandir(entry.path))

    return lines


def file_exists(file_name: str) -> bool:
    """Checks if a file exists in the repository.
    """

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    dirs = list()
    dirs.append(os.scandir(local_repo_path))

    while dirs:
        d = dirs.pop()
        for entry in d:
            if entry.is_file():
                if entry.name.casefold() == file_name:
                    return True
            elif entry.is_dir():
                dirs.append(os.scandir(entry.path))

    return False


def get_repo_contents_local(path: str) -> set:
    """Creates a set of all files in the repository given as path.
    """

    repo = set()

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]
    to_crawl = local_repo_path

    if path:
        to_crawl = os.path.join(local_repo_path, path)
    try:
        contents = os.scandir(to_crawl)
    except Exception as e:
        return repo
    for content in contents:
        repo.add((content.name, content.path))

    contents.close()

    return repo


def get_file_as_yaml(filename):
    root = Path(tmp.tmp_config["Repository"]["local_path"])
    return {
        index: {"content": path.read_text(encoding="utf-8"),
                "path": path.relative_to(root).as_posix()}
        for index, path in enumerate(p for p in source_files() if p.name == filename)
    }


def get_file_as_lines(filename):
    root = Path(tmp.tmp_config["Repository"]["local_path"])
    return {
        index: {"content": path.read_text(encoding="utf-8").splitlines(keepends=True),
                "name": path.name, "path": path.relative_to(root).as_posix()}
        for index, path in enumerate(p for p in source_files() if p.name == filename)
    }
