import argparse
import collections
import csv
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
    parts.close()
    return parts.statistics, parts.vulnerabilities


def main(argv=sys.argv):
    args = _parse_args(argv)
    with args.report:
        split_webinspect_web_application_assessment_report(args.report, args.partsdir)
    return 0


_APPENDIX_LINE = f"Appendix (Check Descriptions){os.linesep}"
_RE_SEVERITY = re.compile(r"^(?P<name>Critical|High|Medium|Low) Issues$")
_RE_VULN_WITH_CAT = re.compile(
    r"^(?P<category>[^:]+): (?P<name>.+) \( (?P<vid>\d+) \)$"
)
_RE_VULN_WITHOUT_CAT = re.compile(r"^(?P<name>[^:]+) \( (?P<vid>\d+) \)$")
_RE_ITEM_START = re.compile(r"^Page:$")
_RE_ITEM_REQUEST = re.compile(r"Request:$")
_RE_ITEM_RESPONSE = re.compile(r"Response:$")
_RE_REQUEST_METHOD_AND_PATH = re.compile(
    r"^(?P<method>GET|POST) /+(?P<section>[^/ ?]*)"
)
_RE_REQUEST_METHOD_ONLY = re.compile(r"^(?P<method>GET|POST)$")
_RE_REQUEST_PATH_ONLY = re.compile(r"^/+(?P<section>[^/ ?]*)")
_RE_JUST_NUMBERS = re.compile(r"^\d+$")


class Vulnerability:
    def __init__(self, vid, category, name):
        self.vid = vid
        self.category = category
        self.name = name

    def __str__(self):
        return ".".join(map(str, [self.vid, self.category, self.name]))


class ReportParser:
    def __iter__(self):
        while not self._end_of_items:
            self._read_next_line()
            if (
                self._check_line_item_start()
                or self._check_line_vulnerability()
                or self._check_line_severity()
                or self._check_line_end_of_items()
            ):
                item = self._make_item_and_advance_if_ready()
                if item:
                    yield item
            else:
                self._append_line()

    def __init__(self, report_stream):
        self._stream = report_stream
        self._lines = iter(self._stream)
        self._item_number = self._line_number = 0
        self._sev = self._vuln = None
        self._next_sev = self._next_vuln = None
        self._item_lines = []
        self._end_of_items = False

    def _make_item_and_advance_if_ready(self):
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
        item = Item(self._item_number, self._sev, self._vuln, self._item_lines,)
        self._item_lines = [self._line]
        self._line = None
        return item

    def _check_line_item_start(self):
        match = _RE_ITEM_START.match(self._line)
        if match:
            self._debug(match)
            return True
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
                match.group("vid"), cat, match.group("name")
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
                file=sys.stderr,
            )


class Item:
    def __init__(
        self, number=None, severity=None, vulnerability=None, lines=None,
    ):
        self.number = _none_or_cast(number, int)
        self.severity = _none_or_cast(severity)
        self.vulnerability = vulnerability
        self.lines = (lines or []).copy()
        self.request_method = self.request_section = None
        if self.severity and self.vulnerability:
            self._parse_details()
        if self.severity:
            if self.vulnerability:
                if self.request_method:
                    self.type_ = "item"
                else:
                    self.type_ = "vulnerability"
            else:
                self.type_ = "severity"
        else:
            self.type_ = "header"

    def is_header(self):
        return self.type_ == "header"

    def is_severity(self):
        return self.type_ == "severity"

    def is_vulnerability(self):
        return self.type_ == "vulnerability"

    def is_item(self):
        return self.type_ == "item"

    def is_pathologically_empty(self):
        if len(self.lines) != 4:
            return False
        if not _RE_ITEM_START.match(self.lines[0]):
            return False
        if self.lines[1] != os.linesep:
            return False
        if not _RE_JUST_NUMBERS.match(self.lines[2]):
            return False
        if self.lines[3] != os.linesep:
            return False
        return True

    def _parse_details(self):
        if self.is_pathologically_empty():
            return
        state = "PRE_START"
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            if state == "PRE_START":
                match = _RE_ITEM_START.match(line)
                if match:
                    state = "AFTER_PAGE"
            elif state == "AFTER_PAGE":
                match = _RE_ITEM_REQUEST.match(line)
                if match:
                    state = "AFTER_REQUEST"
            elif state == "AFTER_REQUEST":
                match = _RE_ITEM_RESPONSE.match(line)
                if match:
                    state == "SKIP_REST"
                else:
                    match = _RE_REQUEST_METHOD_AND_PATH.match(line)
                    if match:
                        self._safe_set_request_method_and_section(
                            match.group("method"), match.group("section")
                        )
                        state = "SKIP_REST"
                    elif i + 1 < len(self.lines):
                        match = _RE_REQUEST_METHOD_ONLY.match(line)
                        if match:
                            method = match.group("method")
                            match = _RE_REQUEST_PATH_ONLY.match(self.lines[i + 1])
                            if match:
                                self._safe_set_request_method_and_section(
                                    method, match.group("section")
                                )
                                i += 1
                                state = "SKIP_REST"
            elif state == "SKIP_REST":
                return
            i += 1

    def _safe_set_request_method_and_section(self, method, section):
        self.request_method = method
        self.request_section = urllib.parse.quote(section, safe="")

    def as_csv_row(self):
        return collections.OrderedDict(
            ItemNumber=self.number,
            Severity=self.severity,
            VulnId=self.vulnerability and self.vulnerability.vid,
            VulnName=self.vulnerability and self.vulnerability.name,
            VulnCat=self.vulnerability and self.vulnerability.category,
            ReqMethod=self.request_method,
            ReqSection=self.request_section,
        )


def _none_or_cast(x, type_=str):
    if x is None:
        return None
    else:
        return type_(x)


class PartsWriter:
    def write_item(self, item):
        if item.is_pathologically_empty():
            return
        self._increment_item_stats(item)
        subpath = Path(str(item.request_section) + "." + str(item.request_method))
        subpath /= str(item.severity)
        subpath /= str(item.vulnerability)
        subpath /= str(f"xx{item.number:06}.txt")
        out = self._open_file(subpath, item)
        out.writelines(item.lines)
        self._close_file_for(item)
        if item.is_item():
            row = item.as_csv_row()
            self._csv_items.writerow(row)

    @property
    def statistics(self):
        return dict(self._stats)

    @property
    def vulnerabilities(self):
        return dict(self._vulns)

    def close(self):
        for target in list(self._files.keys()):
            self._close_file_for(target)

    def __init__(self, partsdir_path):
        self._path = Path(partsdir_path)
        self._path.mkdir(parents=True, exist_ok=True)
        self._stats = {}
        self._vulns = {}
        self._files = {}
        self._csv_items = self._open_csv_writer("items", _CSV_FIELDS_ITEMS)

    def _close_file_for(self, target):
        f = self._files[target]
        f.close()
        del self._files[target]

    def _open_file(self, name, target=None):
        path = self._path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        out = open(path, "w")
        print(f"+ {path}")
        if target:
            self._files[target] = out
        return out

    def _open_csv_writer(self, name, fieldnames):
        out = self._open_file(f"{name}.csv")
        writer = csv.DictWriter(out, fieldnames)
        self._files[writer] = out
        writer.writeheader()
        return writer

    def _increment_item_stats(self, item):
        key = (
            item.severity,
            str(item.vulnerability),
            item.request_method,
            item.request_section,
        )
        if key not in self._stats:
            self._stats[key] = 0
        self._stats[key] += 1
        if item.vulnerability and (item.vulnerability.vid not in self._vulns):
            self._vulns[item.vulnerability.vid] = item.vulnerability


_CSV_FIELDS_ITEMS = list(Item().as_csv_row().keys())


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
