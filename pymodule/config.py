import ConfigParser

def parse_config(conffile, logger):
    def multival_option(option):
        if ',' in option:
            val = map(lambda v: v.strip(), option.split(','))
        else:
            val = [option.strip()] if option else None
        return val

    reqsections = set(['general', 'report'])
    confopts = dict()

    try:
        config = ConfigParser.ConfigParser()
        if config.read(conffile):
            sections = map(lambda v: v.lower(), config.sections())

            diff = reqsections.difference(sections)
            if diff:
                raise ConfigParser.NoSectionError((' '.join(diff)))

            for section in config.sections():
                if section.startswith('General'):
                    confopts['killeverysec'] = float(config.get(section, 'KillEverySec'))
                    confopts['noexec'] = eval(config.get(section, 'NoExecute'))

                    confopts['logmode'] = multival_option(config.get(section, 'LogMode'))
                    if confopts['logmode']:
                        for l in confopts['logmode']:
                            if 'syslog' != l.lower() and 'file' != l.lower():
                                logger.error('Logmode allows only Syslog, File')
                                raise SystemExit(1)
                    else:
                        logger.error('Logmode must define logger')
                        raise SystemExit(1)

                    exusers = multival_option(config.get(section, 'ExcludeUsers'))
                    confopts['excludeusers'] = set(exusers) if exusers else []

                    exprocesses = multival_option(config.get(section, 'ExcludeProcesses'))
                    confopts['excludeprocesses'] = set(exprocesses) if exprocesses else []

                if section.startswith('Report'):
                    confopts['reporteveryhour'] = 3600 * float(config.get(section, 'EveryHours'))
                    confopts['reportfrom'] = config.get(section, 'From')
                    confopts['reportnode'] = config.get(section, 'Node')
                    confopts['reportsmtp'] = config.get(section, 'SMTP')
                    confopts['reportsmtplogin'] = config.get(section, 'SMTPLogin')
                    confopts['reportsmtppass'] = config.get(section, 'SMTPPass')
                    confopts['reportto'] = config.get(section, 'To')
                    confopts['reportsmtpssl'] = eval(config.get(section, 'SMTPSSL'))
                    confopts['sendreport'] = eval(config.get(section, 'Send'))

        else:
            logger.error('Missing %s' % conffile)
            raise SystemExit(1)

    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
        logger.error(e)
        raise SystemExit(1)

    except (ConfigParser.MissingSectionHeaderError, SystemExit) as e:
        if getattr(e, 'filename', False):
            logger.error(e.filename + ' is not a valid configuration file')
            logger.error(e.message)
        raise SystemExit(1)

    return confopts
