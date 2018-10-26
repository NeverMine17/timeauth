# -*- coding: utf-8 -*-

import time
import logging
from . import config


class TimeAuthChecker(object):
    """ Class used to bypass a time based authentication """

    def __init__(self,
                 charset=config.DEFAULT_CHARSET,
                 token_length=config.DEFAULT_TOKEN_LENGTH,
                 base_token="",
                 hidden_char=config.DEFAULT_HIDDEN_CHAR,
                 break_on_time=0):

        """ Checker constructor

        :charset: The charset you need to defined the final token present characters
        :token_length: The length of the result token
        :base_token: If you already found a part of the token, it's not necessary to start from the beguinning
                     if you use this option
        :hidden_char: The character you want to use for the displayed hidden char
        :break_on_time: If you want to stop searching for other offset character when you find a character that took
                        more than break_on_time time unit (in second, can be a float)
        """
        self._charset = charset
        self._token_length = token_length
        self._hidden_char = hidden_char
        self._break_on_time = break_on_time
        self._token = [c for c in base_token] + [self._hidden_char for _ in range(self._token_length - len(base_token))]

    @classmethod
    def _avg(cls, l):

        """ Calculate the average of an uniform list

            :l: The list on which you want to calculate the average.
        """

        return sum(l) / float(len(l))

    def request(self):

        """ Do a request on a server to check the validity of a new token """

        raise NotImplementedError('You should implement this one')

    def get_token(self):

        """ Retrieve the string token stored in the object """

        return ''.join(self._token)

    def _get_token_offsets(self):

        """ Retrieve the token extremities from the length and the hidden char

            exemple: whith self._token = "abc__" : _get_token_offsets() => [0, 2]
        """

        return list(range(len(''.join(self._token).rstrip(self._hidden_char)), self._token_length))

    def _get_timing(self):

        """ Get a time based unit """

        return time.time()

    def _log(self, offset, char, t1, t2, timings, i, best_candidate):

        """ progress loading with average and other informations """

        logging.info("""
                        Testing %d/%d '%c' \\x%x
                        Current Flag: [%s]
                        Took: %s
                        Max: %s:%c
                        Avg: %s
                        """ % (
            i,
            self._token_length,
            char,
            ord(char),
            ''.join(self._token),
            (t2 - t1),
            max(timings),
            best_candidate,
            self._avg(timings)
        ))

    def process(self):

        """ Iterate on token_length and find more intresting char """

        logging.info("Start guessing token ..")
        logging.info('Auth ..')
        for offset in self._get_token_offsets():
            timings = []
            for i, char in enumerate(self._charset):
                self._token[offset] = char
                t1 = self._get_timing()
                self.request()
                t2 = self._get_timing()
                timings.append(t2 - t1)
                best_candidate = self._charset[timings.index(max(timings))]
                self._log(offset, char, t1, t2, timings, i, best_candidate)
                if self._break_on_time != 0:
                    if max(timings) > min(timings) + self._break_on_time:
                        break
            found_char = self._charset[timings.index(max(timings))]
            self._token[offset] = found_char
            logging.info("Found Char: %d:%x:%c - Best: %s - Avg: %s" % (
                ord(found_char),
                ord(found_char),
                found_char,
                max(timings),
                self._avg(timings)
            ))
        logging.info("DONE! %s" % (self.get_token()))

    def print_token(self):

        """ Display the found token """

        logging.info("Your token : [%s]" % self.get_token())
