#!/usr/bin/env python
# -*- coding: utf-8 -*-


class EBBaseUtils(object):

    @staticmethod
    def defval(val, default=None):
        """
        Returns val if is not None, default instead
        :param val:
        :param default:
        :return:
        """
        return val if val is not None else default

    @staticmethod
    def defvalkey(js, key, default=None, take_none=True):
        """
        Returns js[key] if set, otherwise default. Note js[key] can be None.
        :param js:
        :param key:
        :param default:
        :param take_none:
        :return:
        """
        if key not in js:
            return default
        if js[key] is None and not take_none:
            return default
        return js[key]

