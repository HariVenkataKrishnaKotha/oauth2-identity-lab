using Microsoft.EntityFrameworkCore;

namespace ResourceApi.Data;

public class OnboardingDbContext(DbContextOptions<OnboardingDbContext> options) : DbContext(options)
{
    public DbSet<Manager> Managers => Set<Manager>();
    public DbSet<Onboardee> Onboardees => Set<Onboardee>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Manager>().HasIndex(m => m.Login).IsUnique();
        b.Entity<Onboardee>().HasIndex(o => new { o.LastName, o.BirthDate });
    }
}
