"""
Module for coding and encoding Shamir secrets

"""
# from math import ceil
# import base64
import hashlib
import secrets
from uuid import uuid4

import timeutils

# 12th Mersenne prime — larger than any 8-byte (64-bit) secret integer
PRIME = 2**127 - 1

# Upper bound on secret size to avoid unbounded memory use on create_secret()
MAX_SECRET_BYTES = 1_000_000


class InvalidShareError(Exception):
    """
    Raised by populate_decoder() when a submitted share fails validation:
    it is malformed, duplicated, or inconsistent with previously accepted
    shares/metadata for this secret. Distinct from the normal "need more
    shares" case so callers can tell tampering/corruption apart from
    ordinary progress.
    """


class ShareReconstructionError(Exception):
    """
    Raised by decode() when the accepted shares do not combine into a
    valid secret (mismatched checksum, duplicate x-coordinates, or bytes
    that don't decode as UTF-8).
    """


def string_to_integers(input_raw: str, bytes_per_integer: int) -> list:
    """
    Converts any string to a list of (large) integers. This process
    can be inverted by integer_list_to_string() -function
    """
    raw_bytes = input_raw.encode('utf-8')
    byte_length = len(raw_bytes)
    result = [byte_length]
    for i in range(0, byte_length, bytes_per_integer):
        chunk = raw_bytes[i:i + bytes_per_integer]
        chunk = chunk.ljust(bytes_per_integer, b'\x00')  # pad last chunk if needed
        result.append(int.from_bytes(chunk, byteorder='big'))
    return result

def integer_list_to_string(input_list: list, bytes_per_integer: int) -> str:
    """
    Inverts a list of integers created with string_to_integers() back
    to a single string
    """
    byte_length = input_list[0]
    all_bytes = bytearray()
    for integer in input_list[1:]:
        all_bytes.extend(integer.to_bytes(bytes_per_integer, byteorder='big'))
    return bytes(all_bytes[:byte_length]).decode('utf-8')


class ShamirSecret:
    """
    Class for one secret encoding & decoding

    Original secret_raw can be a string of any format
    """

    def __init__(
        self,
        name: str,
        owner: str,
        shares: int = 5,
        treshold: int = 3,
    ):
        """
            Holds exactly one passphrase
            create_secret:
             1. Breaks the passphrase to large integers in plain_text_codes:
                    [byte_length, int1, int2, int3, ...]
             2. Plain_text_codes[1:] are then encrypted by create_shares
                in secret_matrix:
                   [
                    [int_P_1_1, int_P_2_1, int_P_3_1, ...]  # secrets set 1
                    [int_P_1_2, int_P_2_2, int_P_3,2, ...]  # secrets set 2
                    [int_P_1_3, int_P_2_3, int_P_3_3, ...]  # secrets set 3
                    ....
                #   particip1,  particip2, particip3, ---
                   ]
             3. Each secret holder should now be handed all keys in vertical
                axis of this matrix -> iterate_participants

            decrypt secret:
             1. Bring enough (treshold) data to class with populate_decoder
             2. Run decode()
        """
        if shares < 2:
            raise ValueError("shares must be at least 2")
        if treshold < 2:
            # treshold == 1 means every single share IS the secret in the
            # clear (the polynomial degenerates to its constant term) -
            # that defeats the entire point of secret sharing.
            raise ValueError("treshold must be at least 2")
        if treshold > shares:
            raise ValueError("treshold cannot exceed the number of shares")
        self.ready_to_decode = False
        self.treshold = treshold
        self.shares = shares
        self.name = name
        self.owner = owner
        self.uuid = str(uuid4())
        self.secret_matrix: list = []
        self.creation_date = "1800-01-01T00:00:00+00:00"
        self.secret_hash = None
        self.decoding_participants_keys: list = []
        self.bytes_per_integer: int = 8 # Growing this may brake decoding

    def create_secret(self, secret_raw: str)->None:
        if len(secret_raw.encode('utf-8')) > MAX_SECRET_BYTES:
            raise ValueError(
                f"secret exceeds maximum size of {MAX_SECRET_BYTES} bytes"
            )
        plain_text_codes: list = string_to_integers(
            secret_raw,
            self.bytes_per_integer
        )
        self.secret_hash = hashlib.sha256(secret_raw.encode('utf-8')).hexdigest()
        self.creation_date = timeutils.utc_now_iso()
        for plaintext_integer in plain_text_codes:
            self.secret_matrix.append(
                self._generate_shares(
                    self.shares,
                    self.treshold,
                    plaintext_integer))
        self.ready_to_decode = True

    def iterate_participants(self) -> dict:
        """
        Iterator that returns participants' datas as a dict
        after a secret has been created.
        """

        # Create the key data per participant
        participant_data = []
        # for secret_ind, secret in enumerate(self.secret_matrix[0]):
        for secret_ind in range(len(self.secret_matrix[0])):
            # pylint: disable=consider-using-enumerate;
            single_participant_data: list = []
            #for participant_ind, secret_list in enumerate(self.secret_matrix):
            for participant_ind in range(len(self.secret_matrix)):
                single_participant_data.append(
                    self.secret_matrix[participant_ind][secret_ind]
                )
            participant_data.append(single_participant_data)

        # Iterate over the created data
        index = -1
        while index + 1 < len(participant_data):
            index += 1
            yield {
                "keys": participant_data[index],
                "creation_date": self.creation_date,
                "owner": self.owner,
                "name": self.name,
                "uuid": self.uuid,
                "treshold": self.treshold,
                "shares": self.shares,
                "secret_hash": self.secret_hash
            }

    def _validate_keys(self, keys) -> bool:
        """
        Checks that a submitted share list is well-formed: a list of
        (x, y) integer pairs, one per secret chunk, with x within the
        valid field range and not colliding with any x already accepted
        for the same chunk. A repeated x for one chunk would make
        Lagrange interpolation divide by zero, so this also closes off
        a denial-of-service via crafted shares.
        """
        if not isinstance(keys, (list, tuple)) or not keys:
            return False
        if self.decoding_participants_keys and len(keys) != len(self.decoding_participants_keys[0]):
            return False
        for chunk_index, point in enumerate(keys):
            if not isinstance(point, (tuple, list)) or len(point) != 2:
                return False
            x_value, y_value = point
            if not isinstance(x_value, int) or not isinstance(y_value, int):
                return False
            if not 0 < x_value < PRIME:
                return False
            for existing in self.decoding_participants_keys:
                if existing[chunk_index][0] == x_value:
                    return False
        return True

    def populate_decoder(self, participant_data: dict) -> int:
        """
        Takes a participant data dict as input.

        If secret_matrix has values, tests other data to match
        the given essentials and fail if it doesn't

        if secret_matrix empty, populates all settings from
        given participant data. Treshold/shares are sanity-checked
        (treshold >= 2 and treshold <= shares) even on this first,
        bootstrapping submission, so a malicious or corrupted first
        share can't downgrade the treshold - e.g. to 1, where a
        single share equals the secret in the clear. If this decoder
        was constructed with a known expected name/owner (non-empty),
        the first submission is also checked against those.

        last tries to add key data to secret_matrix -list if it
        differs from existing data.

        Returns negative integer of participants key required
        after this operation to decode the secret in all cases.

        Raises InvalidShareError if the submitted share is malformed,
        a duplicate, or inconsistent with previously accepted shares -
        this is distinct from simply needing more shares and should be
        treated as a sign of a corrupted or tampered submission.
        """
        treshold = participant_data["treshold"]
        shares = participant_data["shares"]
        keys = participant_data["keys"]

        if not isinstance(treshold, int) or not isinstance(shares, int):
            raise InvalidShareError("treshold/shares must be integers")
        if treshold < 2 or shares < 2 or treshold > shares:
            raise InvalidShareError("treshold/shares out of valid range")
        if not self._validate_keys(keys):
            raise InvalidShareError(
                "share is malformed, out of range, or duplicates an x-coordinate"
            )

        failed = False
        if not self.decoding_participants_keys:
            if self.name and self.name != participant_data["name"]:
                failed = True
            if self.owner and self.owner != participant_data["owner"]:
                failed = True
        else:
            # Some data in secret_matrix. Check the newly given
            # matches that
            if self.creation_date != participant_data["creation_date"]:
                failed = True
            if self.uuid != participant_data["uuid"]:
                failed = True
            if self.secret_hash != participant_data["secret_hash"]:
                failed = True
            if self.name != participant_data["name"]:
                failed = True
            if self.shares != shares:
                failed = True
            if self.treshold != treshold:
                failed = True

        if keys in self.decoding_participants_keys:
            failed = True

        if failed:
            raise InvalidShareError(
                "share is inconsistent with previously accepted shares for this secret"
            )

        self.decoding_participants_keys.append(keys)
        self.creation_date = participant_data["creation_date"]
        self.owner = participant_data["owner"]
        self.name = participant_data["name"]
        self.uuid = participant_data["uuid"]
        self.secret_hash = participant_data["secret_hash"]
        self.treshold = treshold
        self.shares = shares
        shares_needed = (
            0 - self.treshold + len(self.decoding_participants_keys)
        )
        if shares_needed >= 0:
            self.ready_to_decode = True
        return shares_needed

    def decode(self) -> str:
        """
        Decodes secret string if enough data is inserted via populate_decoder()

        Raises ShareReconstructionError if the accepted shares do not
        combine into a valid secret - this catches corrupted or
        malicious shares that individually passed validation but are
        jointly inconsistent (e.g. don't lie on the original polynomial).
        """
        if not self.ready_to_decode:
            return ""
        decrypted_ints: list = []
        # pylint: disable=unused-variable;
        for key_ind, temp in enumerate(self.decoding_participants_keys[0]):
            this_parts_encrypted_ints: list = []
            for line in self.decoding_participants_keys:
                this_parts_encrypted_ints.append(line[key_ind])
            decrypted_ints.append(self._reconstruct_secret(this_parts_encrypted_ints))
        try:
            result = integer_list_to_string(decrypted_ints, self.bytes_per_integer)
        except (UnicodeDecodeError, IndexError, OverflowError) as exc:
            raise ShareReconstructionError(
                "reconstructed data is not a valid secret - shares may be "
                "corrupted or tampered with"
            ) from exc
        if (
            self.secret_hash is not None
            and hashlib.sha256(result.encode('utf-8')).hexdigest() != self.secret_hash
        ):
            raise ShareReconstructionError(
                "reconstructed secret failed integrity check - shares "
                "may be corrupted or tampered with"
            )
        return result

    def _reconstruct_secret(self, shares: list) -> int:
        """
        Combines individual shares (points on graph)
        using Lagrange interpolation in GF(PRIME).

        `shares` is a list of points (x, y) belonging to a
        polynomial with a constant of our key.
        """
        sums = 0
        for j, share_j in enumerate(shares):
            xj, yj = share_j
            num = 1
            den = 1
            for i, share_i in enumerate(shares):
                xi, _ = share_i
                if i != j:
                    num = (num * (-xi)) % PRIME
                    den = (den * (xj - xi)) % PRIME
            try:
                inv_den = pow(den, -1, PRIME)
            except ValueError as exc:
                raise ShareReconstructionError(
                    "shares contain colliding x-coordinates and cannot be combined"
                ) from exc
            lagrange = (num * inv_den) % PRIME
            sums = (sums + yj * lagrange) % PRIME
        return sums


    def _polynom(self, x, coefficients):
        """
        This generates a single point on the graph of given polynomial
        in `x`. The polynomial is given by the list of `coefficients`.
        All arithmetic is done in GF(PRIME).
        """
        point = 0
        for coefficient_index, coefficient_value in enumerate(
            coefficients[::-1]
        ):
            point = (point + pow(x, coefficient_index, PRIME) * coefficient_value) % PRIME
        return point


    def _coeff(self, treshold, secret):
        """
        Randomly generate a list of coefficients for a polynomial with
        degree of `treshold` - 1, whose constant is `secret`.

        For example with a 3rd degree coefficient like this:
            3x^3 + 4x^2 + 18x + 554

            554 is the secret, and the polynomial degree + 1 is
            how many points are needed to recover this secret.
            (in this case it's 4 points).
        """
        coeff = [secrets.randbelow(PRIME) for _ in range(treshold - 1)]
        coeff.append(secret)
        return coeff


    def _generate_shares(self, n_shares, m, secret) -> list:
        """
        Split given `secret` into `n_shares` shares with minimum threshold
        of `m` shares to recover this `secret`, using SSS algorithm.
        """
        coefficients = self._coeff(m, secret)
        shares = []
        x_values: set = set()

        while len(shares) < n_shares:
            x = secrets.randbelow(PRIME - 1) + 1  # x in [1, PRIME-1]
            if x in x_values:
                continue
            x_values.add(x)
            shares.append((x, self._polynom(x, coefficients)))

        return shares

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.secret_matrix: list = []
        self.decoding_participants_keys: list = []
        self.__init__("","")

    def __enter__(self):
        return self
