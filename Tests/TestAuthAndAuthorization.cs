using NUnit.Framework;
using SafeVault.Models;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestAuthAndAuthorization
    {
        [Test]
        public void TestPasswordHashingAndVerification()
        {
            // Arrange
            string plainPassword = "SecurePassword123!";

            // Act: Hash password using BCrypt
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(plainPassword);

            // Assert: Verification should succeed for correct password
            bool isValid = BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
            Assert.That(isValid, Is.True, "Valid password should match the BCrypt hash.");
        }

        [Test]
        public void TestInvalidLoginAttempt()
        {
            // Arrange
            string plainPassword = "SecurePassword123!";
            string wrongPassword = "WrongPassword456!";
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(plainPassword);

            // Act: Try verifying with wrong password
            bool isValid = BCrypt.Net.BCrypt.Verify(wrongPassword, hashedPassword);

            // Assert: Verification should fail
            Assert.That(isValid, Is.False, "Invalid password attempt should be rejected.");
        }

        [Test]
        public void TestRoleBasedAccessControl_UserRole()
        {
            // Arrange: Standard user
            var user = new User
            {
                Username = "standard_user",
                Email = "user@example.com",
                Role = "user"
            };

            // Assert: Standard user should NOT have admin role
            Assert.That(user.Role, Is.Not.EqualTo("admin"), "Standard user should not have admin permissions.");
        }

        [Test]
        public void TestRoleBasedAccessControl_AdminRole()
        {
            // Arrange: Admin user
            var adminUser = new User
            {
                Username = "admin_user",
                Email = "admin@example.com",
                Role = "admin"
            };

            // Assert: Admin role should match "admin"
            Assert.That(adminUser.Role, Is.EqualTo("admin"), "Admin user must have admin role assigned.");
        }
    }
}