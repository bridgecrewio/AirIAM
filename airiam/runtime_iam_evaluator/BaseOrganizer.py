import datetime as dt


class BaseOrganizer:
    @staticmethod
    def convert_to_list(list_or_single_object):
        if isinstance(list_or_single_object, list):
            return list_or_single_object
        return [list_or_single_object]

    @staticmethod
    def days_from_today(str_date_from_today):
        if str_date_from_today in ['no_information', 'N/A']:
            return 365
        date = dt.datetime.fromisoformat(str_date_from_today).replace(tzinfo=None)
        delta = dt.datetime.now() - date

        return delta.days
