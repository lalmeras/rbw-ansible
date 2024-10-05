# -*- coding: utf-8 -*-
# Copyright (c) 2022, Laurent Almeras <lalmeras@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: rbw
    author:
      - Laurent Almeras <lalmeras@gmail.com>
      - Jonathan Lung (@lungj) <lungj@heresjono.com>
    requirements:
      - rbw (command line utility)
      - rbw vault logged in and unlocked
    short_description: Retrieve secrets from rbw (alternative bitwarden client)
    version_added: X.X.X
    description:
      - Retrieve secrets from rbw.
      - Based on original work on bw from Jonathan Lung.
    options:
      _terms:
        description: Needle passed to rbw get command (uuid, name or uri).
        required: true
        type: list
        elements: str
      field:
        description: Field to fetch. Leave unset to fetch whole response.
        type: str
"""

EXAMPLES = """
- name: "Get 'password' from all Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('rbw', 'a_test', field='password') }}

- name: "Get 'password' from Bitwarden record with ID 'bafba515-af11-47e6-abe3-af1200cd18b2'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('rbw', 'bafba515-af11-47e6-abe3-af1200cd18b2', field='password') | first }}

- name: "Get list of all full Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('rbw', 'a_test') }}

- name: "Get custom field 'api_key' from all Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('rbw', 'a_test', field='api_key') }}
"""

RETURN = """
  _raw:
    description:
      - A one-element list that contains a list of requested fields or JSON objects of matches.
      - If you use C(query), you get a list of lists. If you use C(lookup) without C(wantlist=true),
        this always gets reduced to a list of field values or JSON objects.
    type: list
    elements: list
"""

from subprocess import Popen, PIPE

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.parsing.ajson import AnsibleJSONDecoder
from ansible.plugins.lookup import LookupBase


class RbwException(AnsibleError):
    pass


class Rbw(object):

    def __init__(self, path='rbw'):
        self._cli_path = path

    @property
    def cli_path(self):
        return self._cli_path

    @property
    def unlocked(self):
        _, err = self._run(['unlocked'], stdin="")
        return err is None

    def _run(self, args, stdin=None, expected_rc=0):
        p = Popen([self.cli_path] + args, stdout=PIPE, stderr=PIPE, stdin=PIPE)
        out, err = p.communicate(to_bytes(stdin))
        rc = p.wait()
        if rc != expected_rc:
            if args[0] == "unlocked":
                return "rbw is locked", None
            if len(args) > 2 and args[0] == 'get' and args[1] == 'item' and b'Not found.' in err:
                return 'null', ''
            raise RbwException(err)
        return to_text(out, errors='surrogate_or_strict'), None

    def _get_matches(self, search_value):
        """Return matching records.
        """
        params = search_value
        args = ["get", "--raw", params]
        out, err = self._run(args)
        initial_matches = AnsibleJSONDecoder().raw_decode(out)[0]
        return [initial_matches]

    def get_field(self, field, search_value):
        """Return a list of the specified field for records.

        If field is None, return the whole record for each match.
        """
        matches = self._get_matches(search_value)
        if not field:
            return matches
        field_matches = []
        for match in matches:
            # if there are no custom fields, then `match` has no key 'fields'
            if 'fields' in match:
                custom_field_found = False
                for custom_field in match['fields']:
                    if field == custom_field['name']:
                        field_matches.append(custom_field['value'])
                        custom_field_found = True
                        break
                if custom_field_found:
                    continue
            if 'data' in match and field in match['data']:
                field_matches.append(match['data'][field])
                continue
            if field in match:
                field_matches.append(match[field])
                continue

        if matches and not field_matches:
            raise AnsibleError("field {field} does not exist in {search_value}".format(field=field, search_value=search_value))

        return field_matches


class LookupModule(LookupBase):

    def run(self, terms=None, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        field = self.get_option('field')

        if not _rbw.unlocked:
            raise AnsibleError("rbw vault locked. Run 'rbw unlock'.")

        if not terms:
            terms = [None]

        return [_rbw.get_field(field, term) for term in terms]


_rbw = Rbw()