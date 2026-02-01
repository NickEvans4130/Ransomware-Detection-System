# Troubleshooting Guide

## Common Issues

### Monitor Not Detecting Events
- Check if directories are configured correctly in config.json
- Verify watchdog library is installed
- Ensure sufficient permissions to read target directories
- Check logs for error messages

### High False Positive Rate
- Adjust thresholds in detection_config.json
- Add legitimate processes to whitelist
- Review entropy threshold (may need tuning for your file types)
- Check if backup software is triggering false positives

### Performance Issues
- Reduce number of monitored directories
- Increase time window for aggregation
- Disable entropy analysis for certain file types
- Check database size (vacuum if too large)

### Backup System Not Working
- Verify write permissions to backup_vault directory
- Check available disk space
- Review backup retention settings
- Ensure backup location is not on same volume as monitored files

### Dashboard Not Loading
- Check if Flask server is running
- Verify port 5000 is not blocked by firewall
- Check browser console for JavaScript errors
- Ensure database is accessible

### Cannot Restore Files
- Verify backups exist in backup_vault
- Check file paths are correct
- Ensure sufficient permissions
- Review recovery logs for errors

## Debug Mode
Enable debug logging by setting LOG_LEVEL=DEBUG in config