using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityService.Models
{
    public class ApplicationUserRole : IdentityUserRole<string>
    {
        [MaxLength(36)]
        public override string UserId { get => base.UserId; set => base.UserId = value; }

        [MaxLength(36)]
        public override string RoleId { get => base.RoleId; set => base.RoleId = value; }
    }
}
