using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ResourceApi.Data;

[Table("Managers")]
public class Manager
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(256)]
    public string Login { get; set; } = default!;

    [Required, MaxLength(256)]
    public string PasswordPlain { get; set; } = default!; // test only

    [MaxLength(256)]
    public string? Email { get; set; }

    // Navigation property
    public ICollection<Onboardee> Onboardees { get; set; } = new List<Onboardee>();
}

[Table("Onboardees")]
public class Onboardee
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(128)]
    public string FirstName { get; set; } = default!;

    [Required, MaxLength(128)]
    public string LastName { get; set; } = default!;

    [Required]
    public DateOnly BirthDate { get; set; }

    [Required]
    public Guid ManagerId { get; set; }

    // Navigation property
    [ForeignKey(nameof(ManagerId))]
    public Manager? Manager { get; set; }
}