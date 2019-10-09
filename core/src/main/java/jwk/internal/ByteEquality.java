package jwk.internal;

import scodec.bits.ByteVector;

public abstract class ByteEquality {
    private ByteEquality() {
    }

    /**
     * Constant-time byte comparison.
     *
     * @param b a byte
     * @param c a byte
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(int b, int c) {
        int result = 0;
        int xor = b ^ c;
        for (int i = 0; i < 8; i++) {
            result |= xor >> i;
        }
        return (result ^ 0x01) & 0x01;
    }

    /**
     * Constant-time byte[] comparison.
     *
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(byte[] b, byte[] c, int length) {
        int result = 0;
        for (int i = 0; i < length; i++) {
            result |= b[i] ^ c[i];
        }

        return equal(result, 0);
    }

    public static boolean equal(ByteVector a, ByteVector b) {
        if (a.size() == b.size()) {
            return equal(a.toArray(), b.toArray(), (int) a.size()) == 1;
        }
        return false;
    }
}
