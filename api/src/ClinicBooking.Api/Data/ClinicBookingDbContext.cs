using ClinicBooking.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace ClinicBooking.Api.Data;

public sealed class ClinicBookingDbContext(DbContextOptions<ClinicBookingDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<Appointment> Appointments => Set<Appointment>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Appointment>(entity =>
        {
            entity.HasKey(appointment => appointment.Id);
            entity.Property(appointment => appointment.PatientId)
                .HasMaxLength(200)
                .IsRequired();
            entity.Property(appointment => appointment.DoctorId)
                .HasMaxLength(200)
                .IsRequired();
            entity.Property(appointment => appointment.ScheduledAt)
                .IsRequired();
            entity.Property(appointment => appointment.Status)
                .HasConversion<string>()
                .HasMaxLength(32)
                .IsRequired();

            entity.HasIndex(appointment => appointment.PatientId);
            entity.HasIndex(appointment => appointment.DoctorId);
            entity.HasIndex(appointment => appointment.ScheduledAt);
        });
    }
}
