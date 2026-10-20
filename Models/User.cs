using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;

namespace SafeVault.Models
{
    public class User
    {
        public int UserID { get; set; }

        [Required(ErrorMessage = "Username is required.")]
        [StringLength(100, MinimumLength = 3)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        // Securely stores the BCrypt hashed password
        public string PasswordHash { get; set; } = string.Empty;

        // User role for authorization ("user" or "admin")
        public string Role { get; set; } = "user";

        public void Sanitize(HtmlEncoder encoder)
        {
            ArgumentNullException.ThrowIfNull(encoder);

            Username = encoder.Encode(Username ?? string.Empty);
            Email = encoder.Encode(Email ?? string.Empty);
        }
    }
}