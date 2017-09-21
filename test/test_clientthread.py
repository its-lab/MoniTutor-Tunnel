from server.clientthread import ClientThread
import random
import string
import unittest

class ClientThreadTestCase(unittest.TestCase):

    def setUp(self):
        self.client = ClientThread(" ")
        pass

    def generate_random_string(self, length):
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(length))

    def test_message_parser(self):
        shortmessage = self.generate_random_string(10)
        self.assertEqual(
                ([shortmessage],""),
                self.client._get_message_from_chunks("\x02"+shortmessage+"\x03",""))
        long_message = self.generate_random_string(500)
        self.assertEqual(
                ([long_message],""),
                self.client._get_message_from_chunks("\x02"+long_message+"\x03",""))
        self.assertEqual(
                ([shortmessage+shortmessage],""),
                self.client._get_message_from_chunks(shortmessage+"\x03",shortmessage))
        self.assertEqual(
                ([shortmessage,shortmessage],""),
                self.client._get_message_from_chunks(shortmessage+"\x03"+"\x02"+shortmessage+"\x03",""))

