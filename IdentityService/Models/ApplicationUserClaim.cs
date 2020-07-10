using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityService.Models
{
    public class ApplicationUserClaim : IdentityUserClaim<string>
    {
        [MaxLength(36)]
        public override string UserId { get => base.UserId; set => base.UserId = value; }
    }
}
