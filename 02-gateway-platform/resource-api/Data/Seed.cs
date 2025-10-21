namespace ResourceApi.Data;

public static class Seed
{
    public static async Task EnsureAsync(OnboardingDbContext db)
    {
        await db.Database.EnsureCreatedAsync();

        if (!db.Managers.Any())
        {
            var m1 = new Manager { Login = "manager1@example.com", PasswordPlain = "P@ssw0rd!123", Email = "manager1@example.com" };
            var m2 = new Manager { Login = "manager2@example.com", PasswordPlain = "P@ssw0rd!123", Email = "manager2@example.com" };
            db.Managers.AddRange(m1, m2);

            db.Onboardees.AddRange(
                new Onboardee { FirstName = "Ava", LastName = "Johnson", BirthDate = new DateOnly(1995, 3, 12), ManagerId = m1.Id },
                new Onboardee { FirstName = "Liam", LastName = "Johnson", BirthDate = new DateOnly(1999, 9, 1), ManagerId = m1.Id },
                new Onboardee { FirstName = "Maya", LastName = "Patel", BirthDate = new DateOnly(2000, 1, 25), ManagerId = m2.Id }
            );
            await db.SaveChangesAsync();
        }
    }
}
