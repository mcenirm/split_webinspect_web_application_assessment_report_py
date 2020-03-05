import argparse
import os
import re
import sys
import urllib.parse
from pathlib import Path


def split_webinspect_web_application_assessment_report(report_stream, partsdir_path):
    parts = PartsWriter(partsdir_path)
    parser = ReportParser(report_stream)
    for item in parser:
        parts.write_item(item)
    return parts.statistics, parts.vulnerabilities


def main(argv=sys.argv):
    args = _parse_args(argv)
    with args.report:
        split_webinspect_web_application_assessment_report(args.report, args.partsdir)
    return 0


_APPENDIX_LINE = f"Appendix (Check Descriptions){os.linesep}"
_RE_SEVERITY = re.compile(r"^(?P<name>Critical|High|Medium|Low) Issues$")
_RE_VULN_WITH_CAT = re.compile(
    r"^(?P<category>[^:]+): (?P<name>.+) \( (?P<number>\d+) \)$"
)
_RE_VULN_WITHOUT_CAT = re.compile(r"^(?P<name>[^:]+) \( (?P<number>\d+) \)$")
_RE_ITEM_START = re.compile(r"^Page:$")
_RE_REQUEST = re.compile(r"^(?P<method>GET|POST) /(?P<section>[^/ ]+)")


class Vulnerability:
    def __init__(self, number, category, name):
        self.number = number
        self.category = category
        self.name = name

    def __str__(self):
        return ".".join(map(str, [self.number, self.category, self.name]))


class ReportParser:
    def __iter__(self):
        return self

    def __next__(self):
        try:
            while not self._end_of_items:
                self._read_next_line()
                if (
                    self._check_line_item_start()
                    or self._check_line_vulnerability()
                    or self._check_line_severity()
                    or self._check_line_end_of_items()
                ):
                    item = self._make_item_if_ready()
                    if item:
                        return item
                else:
                    self._check_line_request()
                    self._append_line()
        except StopIteration:
            raise
        raise StopIteration

    def __init__(self, report_stream):
        self._stream = report_stream
        self._lines = iter(self._stream)
        self._item_number = self._line_number = 0
        self._sev = self._vuln = None
        self._request_method = self._request_section = None
        self._next_sev = self._next_vuln = None
        self._item_lines = []
        self._end_of_items = False

    def _make_item_if_ready(self):
        item = None
        if self._item_lines and self._vuln and self._sev:
            item = self._make_item()
        if self._next_vuln:
            self._vuln = self._next_vuln
            self._next_vuln = None
        if self._next_sev:
            self._sev = self._next_sev
            self._next_sev = None
        return item

    def _make_item(self):
        self._item_number += 1
        item = Item(
            self._item_number,
            self._sev,
            self._vuln,
            self._request_method,
            self._request_section,
            self._item_lines,
        )
        self._request_method = self._request_section = None
        self._item_lines = [self._line]
        self._line = None
        return item

    def _check_line_item_start(self):
        match = _RE_ITEM_START.match(self._line)
        if match:
            self._debug(match)
            return True
        return False

    def _check_line_request(self):
        match = _RE_REQUEST.match(self._line)
        if match:
            self._debug(match)
            self._request_method = match.group("method")
            self._request_section = urllib.parse.quote(match.group("section"), safe="")
        # never start a new item
        return False

    def _check_line_vulnerability(self):
        match = _RE_VULN_WITH_CAT.match(self._line)
        if match:
            cat = match.group("category")
        else:
            match = _RE_VULN_WITHOUT_CAT.match(self._line)
            cat = "_"
        if match:
            self._debug(match)
            self._next_vuln = Vulnerability(
                match.group("number"), cat, match.group("name")
            )
            return True
        return False

    def _check_line_severity(self):
        match = _RE_SEVERITY.match(self._line)
        if match:
            self._debug(match)
            self._next_sev = match.group("name")
            self._next_vuln = None
            return True
        return False

    def _check_line_end_of_items(self):
        if self._line == _APPENDIX_LINE:
            self._debug(repr(self._line))
            self._end_of_items = True
            return True
        return False

    def _read_next_line(self):
        line = next(self._lines)
        self._line_number += 1
        self._line = line

    def _append_line(self):
        self._item_lines.append(self._line)

    def _debug(self, *extras):
        if os.environ.get("DEBUG_SPLIT_WEBINSPECT", None):
            print(
                self._line_number,
                len(self._item_lines),
                self._sev,
                *extras,
                file=sys.stdout,
            )


class Item:
    def __init__(
        self, number, severity, vulnerability, request_method, request_section, lines,
    ):
        self.number = _none_or_cast(number, int)
        self.severity = _none_or_cast(severity)
        self.vulnerability = vulnerability
        self.request_method = _none_or_cast(request_method)
        self.request_section = _none_or_cast(request_section)
        self.lines = (lines or []).copy()


def _none_or_cast(x, type_=str):
    if x is None:
        return None
    else:
        return type_(x)


class PartsWriter:
    def write_item(self, item):
        self._increment_item_stats(item)
        subpath = Path(str(item.request_section) + "." + str(item.request_method))
        subpath /= str(item.severity)
        subpath /= str(item.vulnerability)
        subpath /= str(f"xx{item.number:06}.txt")
        self._open_file(item, subpath).writelines(item.lines)

    @property
    def statistics(self):
        return dict(self._stats)

    @property
    def vulnerabilities(self):
        return dict(self._vulns)

    def __init__(self, partsdir_path):
        self._path = Path(partsdir_path)
        self._path.mkdir(parents=True, exist_ok=True)
        self._stats = {}
        self._vulns = {}

    def _open_file(self, target, name):
        path = self._path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        out = open(path, "w")
        print(f"+ {path}")
        return out

    def _increment_item_stats(self, item):
        key = (
            item.severity,
            item.vulnerability.number,
            item.request_method,
            item.request_section,
        )
        if key not in self._stats:
            self._stats[key] = 0
        self._stats[key] += 1
        if item.vulnerability.number not in self._vulns:
            self._vulns[item.vulnerability.number] = item.vulnerability


def _parse_args(argv):
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument(
        "report",
        help="Which report file to split",
        type=argparse.FileType("r", encoding="UTF-8"),
        metavar="REPORT.txt",
    )
    parser.add_argument(
        "partsdir",
        help="Where to store report parts",
        type=_missing_or_empty_dir_path,
        metavar="PARTSDIR",
    )
    args = parser.parse_args(argv[1:])
    return args


def _missing_or_empty_dir_path(the_string):
    "Complains if the directory argument exists but is not empty"
    the_path = Path(the_string)
    complaint = None
    if the_path.exists():
        if the_path.is_dir():
            if any(the_path.iterdir()):
                complaint = "exists but is not empty"
            else:
                pass  # Empty dir is good
        else:
            complaint = "exists but is not a directory"
    else:
        pass  # Missing dir is good
    if complaint:
        raise argparse.ArgumentTypeError(f"{the_path} {complaint}")
    return the_path


if __name__ == "__main__":
    sys.exit(main())
