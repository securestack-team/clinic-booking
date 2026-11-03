namespace ClinicBooking.Api.Models;

public sealed class Appointment
{
    public Guid Id { get; set; }

    public required string PatientId { get; set; }

    public required string DoctorId { get; set; }

    public DateTimeOffset ScheduledAt { get; set; }

    public AppointmentStatus Status { get; set; } = AppointmentStatus.Scheduled;
}

public enum AppointmentStatus
{
    Scheduled,
    Confirmed,
    Completed,
    Cancelled
}
