"""A suite of tests for Mailjet API client functionality."""

import os
import random
import string
import unittest
from pathlib import Path
from typing import Any
from typing import ClassVar

from mailjet_rest import Client


class TestSuite(unittest.TestCase):
    """A suite of tests for Mailjet API client functionality.

    This class provides setup and teardown functionality for tests involving the
    Mailjet API client, with authentication and client initialization handled
    in `setUp`. Each test in this suite operates with the configured Mailjet client
    instance to simulate API interactions.
    """

    def setUp(self) -> None:
        """Set up the test environment by initializing authentication credentials and the Mailjet client.

        This method is called before each test to ensure a consistent testing
        environment. It retrieves the API keys from environment variables and
        uses them to create an instance of the Mailjet `Client` for authenticated
        API interactions.

        Attributes:
        - self.auth (tuple[str, str]): A tuple containing the public and private API keys obtained from the environment variables 'MJ_APIKEY_PUBLIC' and 'MJ_APIKEY_PRIVATE' respectively.
        - self.client (Client):  An instance of the Mailjet Client class, initialized with the provided authentication credentials.
        """
        self.auth: tuple[str, str] = (
            os.environ["MJ_APIKEY_PUBLIC"],
            os.environ["MJ_APIKEY_PRIVATE"],
        )
        self.client: Client = Client(auth=self.auth)

    def test_get_no_param(self) -> None:
        """This test function sends a GET request to the Mailjet API endpoint for contacts without any parameters.

        It verifies that the response contains 'Data' and 'Count' fields.

        Parameters:
        None
        """
        result: Any = self.client.contact.get().json()
        self.assertTrue("Data" in result and "Count" in result)

    def test_get_valid_params(self) -> None:
        """This test function sends a GET request to the Mailjet API endpoint for contacts with a valid parameter 'limit'.

        It verifies that the response contains a count of contacts that is within the range of 0 to 2.

        Parameters:
        None
        """
        result: Any = self.client.contact.get(filters={"limit": 2}).json()
        self.assertTrue(result["Count"] >= 0 or result["Count"] <= 2)

    def test_get_invalid_parameters(self) -> None:
        """This test function sends a GET request to the Mailjet API endpoint for contacts with an invalid parameter.

        It verifies that the response contains 'Count' field, demonstrating that invalid parameters are ignored.

        Parameters:
        None
        """
        # invalid parameters are ignored
        result: Any = self.client.contact.get(filters={"invalid": "false"}).json()
        self.assertTrue("Count" in result)

    def test_get_with_data(self) -> None:
        """This test function sends a GET request to the Mailjet API endpoint for contacts with 'data' parameter.

        It verifies that the request is successful (status code 200) and does not use the 'data' parameter.

        Parameters:
        None
        """
        # it shouldn't use data
        result = self.client.contact.get(data={"Email": "api@mailjet.com"})
        self.assertTrue(result.status_code == 200)

    def test_get_with_action(self) -> None:
        """This function tests the functionality of adding a contact to a contact list using the Mailjet API client.

        It first retrieves a contact and a contact list from the API, then adds the contact to the list.
        Finally, it verifies that the contact has been successfully added to the list.

        Parameters:
        None

        Attributes:
        - get_contact (Any): The result of the initial contact retrieval, containing a single contact.
        - contact_id (str): The ID of the retrieved contact.
        - post_contact (Response): The response from creating a new contact if no contact was found.
        - get_contact_list (Any): The result of the contact list retrieval, containing a single contact list.
        - list_id (str): The ID of the retrieved contact list.
        - post_contact_list (Response): The response from creating a new contact list if no contact list was found.
        - data (dict[str, list[dict[str, str]]]): The data for managing contact lists, containing the list ID and action to add the contact.
        - result_add_list (Response): The response from adding the contact to the contact list.
        - result (Any): The result of retrieving the contact's contact lists, containing the count of contact lists.
        """
        get_contact: Any = self.client.contact.get(filters={"limit": 1}).json()
        if get_contact["Count"] != 0:
            contact_id: str = get_contact["Data"][0]["ID"]
        else:
            contact_random_email: str = (
                "".join(
                    random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(10)
                )
                + "@mailjet.com"
            )
            post_contact = self.client.contact.create(
                data={"Email": contact_random_email},
            )
            self.assertTrue(post_contact.status_code == 201)
            contact_id = post_contact.json()["Data"][0]["ID"]

        get_contact_list: Any = self.client.contactslist.get(
            filters={"limit": 1},
        ).json()
        if get_contact_list["Count"] != 0:
            list_id: str = get_contact_list["Data"][0]["ID"]
        else:
            contact_list_random_name: str = (
                "".join(
                    random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(10)
                )
                + "@mailjet.com"
            )
            post_contact_list = self.client.contactslist.create(
                data={"Name": contact_list_random_name},
            )
            self.assertTrue(post_contact_list.status_code == 201)
            list_id = post_contact_list.json()["Data"][0]["ID"]

        data: dict[str, list[dict[str, str]]] = {
            "ContactsLists": [{"ListID": list_id, "Action": "addnoforce"}],
        }
        result_add_list = self.client.contact_managecontactslists.create(
            id=contact_id,
            data=data,
        )
        self.assertTrue(result_add_list.status_code == 201)

        result = self.client.contact_getcontactslists.get(contact_id).json()
        self.assertTrue("Count" in result)

    def test_get_with_id_filter(self) -> None:
        """This test function sends a GET request to the Mailjet API endpoint for contacts with a specific email address obtained from a previous contact retrieval.

        It verifies that the response contains a contact with the same email address as the one used in the filter.

        Parameters:
        None

        Attributes:
        - result_contact (Any): The result of the initial contact retrieval, containing a single contact.
        - result_contact_with_id (Any): The result of the contact retrieval using the email address from the initial contact as a filter.
        """
        result_contact: Any = self.client.contact.get(filters={"limit": 1}).json()
        result_contact_with_id: Any = self.client.contact.get(
            filter={"Email": result_contact["Data"][0]["Email"]},
        ).json()
        self.assertTrue(
            result_contact_with_id["Data"][0]["Email"]
            == result_contact["Data"][0]["Email"],
        )

    def test_post_with_no_param(self) -> None:
        """This function tests the behavior of the Mailjet API client when attempting to create a sender with no parameters.

        The function sends a POST request to the Mailjet API endpoint for creating a sender with an empty
        data dictionary. It then verifies that the response contains a 'StatusCode' field with a value of 400,
        indicating a bad request. This test ensures that the client handles missing required parameters
        appropriately.

        Parameters:
        None
        """
        result: Any = self.client.sender.create(data={}).json()
        self.assertTrue("StatusCode" in result and result["StatusCode"] == 400)

    def test_client_custom_version(self) -> None:
        """This test function verifies the functionality of setting a custom version for the Mailjet API client.

        The function initializes a new instance of the Mailjet Client with custom version "v3.1".
        It then asserts that the client's configuration version is correctly set to "v3.1".
        Additionally, it verifies that the send endpoint URL in the client's configuration is updated to the correct version.

        Parameters:
        None
        """
        self.client = Client(auth=self.auth, version="v3.1")
        self.assertEqual(self.client.config.version, "v3.1")
        self.assertEqual(
            self.client.config["send"][0],
            "https://api.mailjet.com/v3.1/send",
        )

    def test_user_agent(self) -> None:
        """This function tests the user agent configuration of the Mailjet API client.

        The function initializes a new instance of the Mailjet Client with a custom version "v3.1".
        It then asserts that the client's user agent is correctly set to "mailjet-apiv3-python/v1.3.5".
        This test ensures that the client's user agent is properly configured and includes the correct version information.

        Parameters:
        None
        """
        self.client = Client(auth=self.auth, version="v3.1")
        self.assertEqual(self.client.config.user_agent, "mailjet-apiv3-python/v1.5.0")


class TestCsvImport(unittest.TestCase):
    """Tests for Mailjet API csv import functionality.

    This class provides setup and teardown functionality for tests involving the
    csv import functionality, with authentication and client initialization handled
    in `setUp`. Each test in this suite operates with the configured Mailjet client
    instance to simulate API interactions.

    Attributes:
    - _shared_state (dict[str, str]): A dictionary containing values taken from tests to share them in other tests.
    """

    _shared_state: ClassVar[dict[str, Any]] = {}

    @classmethod
    def get_shared(cls, key: str) -> Any:
        """Retrieve a value from shared test state.

        Parameters:
        - key (str): The key to look up in shared state.

        Returns:
        - Any: The stored value, or None if key doesn't exist.
        """
        return cls._shared_state.get(key)

    @classmethod
    def set_shared(cls, key: str, value: Any) -> None:
        """Store a value in shared test state.

        Parameters:
        - key (str): The key to store the value under.
        - value (Any): The value to store.
        """
        cls._shared_state[key] = value

    def setUp(self) -> None:
        """Set up the test environment by initializing authentication credentials and the Mailjet client.

        This method is called before each test to ensure a consistent testing
        environment. It retrieves the API keys and ID_CONTACTSLIST from environment variables and
        uses them to create an instance of the Mailjet `Client` for authenticated
        API interactions.

        Attributes:
        - self.auth (tuple[str, str]): A tuple containing the public and private API keys obtained from the environment variables 'MJ_APIKEY_PUBLIC' and 'MJ_APIKEY_PRIVATE' respectively.
        - self.client (Client): An instance of the Mailjet Client class, initialized with the provided authentication credentials.
        - self.id_contactslist (str): A string of the contacts list ID from https://app.mailjet.com/contacts
        """
        self.auth: tuple[str, str] = (
            os.environ["MJ_APIKEY_PUBLIC"],
            os.environ["MJ_APIKEY_PRIVATE"],
        )
        self.client: Client = Client(auth=self.auth)
        self.id_contactslist: str = os.environ["ID_CONTACTSLIST"]

    def test_01_upload_the_csv(self) -> None:
        """Test uploading a csv file.

        POST https://api.mailjet.com/v3/DATA/contactslist
        /$ID_CONTACTLIST/CSVData/text:plain
        """
        result = self.client.contactslist_csvdata.create(
            id=self.id_contactslist,
            data=Path("tests/doc_tests/files/data.csv").read_text(encoding="utf-8"),
        )
        self.assertEqual(result.status_code, 200)

        self.set_shared("data_id", result.json().get("ID"))
        data_id = self.get_shared("data_id")
        self.assertIsNotNone(data_id)

    def test_02_import_csv_content_to_a_list(self) -> None:
        """Test importing a csv content to a list.

        POST https://api.mailjet.com/v3/REST/csvimport
        """
        data_id = self.get_shared("data_id")
        self.assertIsNotNone(data_id)
        data = {
            "Method": "addnoforce",
            "ContactsListID": self.id_contactslist,
            "DataID": data_id,
        }
        result = self.client.csvimport.create(data=data)
        self.assertEqual(result.status_code, 201)
        self.assertIn("ID", result.json()["Data"][0])

        self.set_shared("id_value", result.json()["Data"][0]["ID"])

    def test_03_monitor_the_import_progress(self) -> None:
        """Test getting a csv content import.

        GET https://api.mailjet.com/v3/REST/csvimport/$importjob_ID
        """
        result = self.client.csvimport.get(id=self.get_shared("id_value"))
        self.assertEqual(result.status_code, 200)
        self.assertIn("ID", result.json()["Data"][0])
        self.assertEqual(0, result.json()["Data"][0]["Errcount"])


if __name__ == "__main__":
    unittest.main()
