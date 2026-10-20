using NUnit.Framework;
using SafeVault.Models;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        // Helper method to simulate ASP.NET Core DataAnnotation validation
        private bool ValidateModel(object model, out List<ValidationResult> results)
        {
            var context = new ValidationContext(model, null, null);
            results = new List<ValidationResult>();
            return Validator.TryValidateObject(model, context, results, true);
        }

        [Test]
        public void SqlInjectionPayload_IsRejectedByValidation()
        {
            // Arrange: SQL Injection payload in Username
            var model = new User
            {
                Username = "admin' OR '1'='1",
                Email = "test@example.com"
            };

            // Act
            bool isValid = ValidateModel(model, out var results);

            // Assert: Validation should fail because of special characters
            Assert.That(isValid, Is.False, "SQL Injection payload should be rejected.");
        }

        [Test]
        public void XssPayload_IsRejectedByValidation()
        {
            // Arrange: Cross-Site Scripting payload in Username
            var model = new User
            {
                Username = "<script>alert('xss')</script>",
                Email = "test@example.com"
            };

            // Act
            bool isValid = ValidateModel(model, out var results);

            // Assert: Validation should fail because of script tags
            Assert.That(isValid, Is.False, "XSS script tags should be rejected.");
        }

        [Test]
        public void SqlInjectionPayload_IsEncodedBySanitization()
        {
            var payload = "admin' OR '1'='1";
            var model = new User
            {
                Username = payload,
                Email = "test@example.com"
            };

            model.Sanitize(HtmlEncoder.Default);

            Assert.That(model.Username, Is.Not.EqualTo(payload));
            Assert.That(model.Username, Does.Not.Contain("'"));
            Assert.That(model.Email, Is.EqualTo("test@example.com"));
        }

        [Test]
        public void XssPayload_IsEncodedBySanitization()
        {
            var payload = "<script>alert('xss')</script>";
            var model = new User
            {
                Username = payload,
                Email = "test@example.com"
            };

            model.Sanitize(HtmlEncoder.Default);

            Assert.That(model.Username, Is.Not.EqualTo(payload));
            Assert.That(model.Username, Does.Not.Contain("<script>"));
            Assert.That(model.Username, Does.Contain("&lt;script&gt;"));
            Assert.That(model.Email, Is.EqualTo("test@example.com"));
        }

        [Test]
        public void TestValidInput()
        {
            // Arrange: Valid username and email
            var model = new User
            {
                Username = "ValidUser123",
                Email = "valid@example.com"
            };

            // Act
            bool isValid = ValidateModel(model, out var results);

            // Assert: Validation should pass
            Assert.That(isValid, Is.True, "Valid input should pass validation.");
        }
    }
}