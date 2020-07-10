using System;
using System.Collections.Generic;
using System.Text;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string, ApplicationUserClaim, ApplicationUserRole, ApplicationUserLogin, ApplicationRoleClaim, ApplicationUserToken>
    {
        public ApplicationDbContext(DbContextOptions options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>().ToTable("users");
            builder.Entity<ApplicationUser>(entity => {
                entity.Property(m => m.Email).HasMaxLength(128);
                entity.Property(m => m.NormalizedEmail).HasMaxLength(128);
                entity.Property(m => m.UserName).HasMaxLength(128);
                entity.Property(m => m.NormalizedUserName).HasMaxLength(128);
            });

            builder.Entity<ApplicationRole>().ToTable("roles");
            builder.Entity<ApplicationRole>(entity => {
                entity.Property(m => m.Name).HasMaxLength(128);
                entity.Property(m => m.NormalizedName).HasMaxLength(128);
            });

            builder.Entity<ApplicationUserClaim>().ToTable("user_claims");

            builder.Entity<ApplicationUserRole>().ToTable("user_roles");

            builder.Entity<ApplicationUserLogin>().ToTable("user_logins");

            builder.Entity<ApplicationRoleClaim>().ToTable("role_claims");

            builder.Entity<ApplicationUserToken>().ToTable("user_tokens");
        }
    }
}
