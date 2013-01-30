import datetime
import time

class NxFilter(object):

    def GetMatchesFromValues(self, filters, data):
        self.__filters = filters
        self.__data = data
        ret_dict = []
        for row in self.__data:
            row = dict(row)
            l = {}
            match = 0
            for var in self.__filters:
                if isinstance(self.__filters[var], list):
                    for val in self.__filters[var]:
                        if val == row[var]:
                            match += 1
                            l.update(row)
                            break
                else:
                    if row[var] == self.__filters[var]:
                        match += 1
                        l.update(row)
            if match < len(self.__filters):
                l = {}

            if l != {}:
                ret_dict.append(l)
        return ret_dict

    def GetMatchesFromDates(self, date_range, data):
        if data[0].get('date') is None:
            raise Exception, "No date field !"

        if date_range.startswith('-'):
            end =  time.strptime(date_range[1:], "%Y/%m/%d")
            start = time.strptime(str(datetime.date.min), "%Y-%m-%d")
        elif date_range.endswith('-'):
            start = time.strptime(date_range[:-1], "%Y/%m/%d")
            end = time.strptime(str(datetime.date.today()), "%Y-%m-%d")
        else:
            start, end = date_range.split('-')
            start =  time.strptime(start, "%Y/%m/%d")
            end =  time.strptime(end, "%Y/%m/%d")

        print start, end
        
