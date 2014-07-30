SecureString
=============

This is a quickly knocked off attempt to have a more secure String handler
for Java. It misses about every String function; if you want that, you can
add it. It's main feature is to have Strings held in memory not as a String,
but as a char array; and even to have them expiring after some time.

DESCRIPTION
=============

See the TestSecureString class for samples on how to use it. Essentially,
what SecureString does is that it always converts the String into a char
array, hence avoiding it to survive too long on the heap. In addition,
you can tell it to expire; if you do, it will create a separate thread
which will check for whether or not to nullify that char array. And,
you can tell it to actually not even store itself as a char array, but
as a hash; in that case, it will convert it into a md5 version and
continue working with that.

The only really overloaded methods - besides the timeout thread - are the
toString and equals methods which take care of the hashing etc.

TESTING
=============

The JUnit tests use junit-4.11.jar plus hamcrest-core-1.3.jar because we
want to look more awesome by running tests in parallel. And because both
are rather small, we even commit them.

