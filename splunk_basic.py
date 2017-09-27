from bloomfilter import Bloomfilter
from segmenter import segments

class Splunk(object):
    def __init__(self):
        self.bf = Bloomfilter(64)
        self.terms = {}  # Dictionary of term to set of events
        self.events = []
    
    def add_event(self, event):
        """Adds an event to this object"""

        # Generate a unique ID for the event, and save it
        event_id = len(self.events)
        self.events.append(event)

        # Add each term to the bloomfilter, and track the event by each term
        for term in segments(event):
            self.bf.add_value(term)

            if term not in self.terms:
                self.terms[term] = set()
            self.terms[term].add(event_id)

    def search(self, term):
        """Search for a single term, and yield all the events that contain it"""
        
        # In Splunk this runs in O(1), and is likely to be in filesystem cache (memory)
        if not self.bf.might_contain(term):
            return

        # In Splunk this probably runs in O(log N) where N is the number of terms in the tsidx
        if term not in self.terms:
            return

        for event_id in sorted(self.terms[term]):
            yield self.events[event_id]


def main():
    s = Splunk()
    s.add_event('src_ip = 1.2.3.4')
    s.add_event('src_ip = 5.6.7.8')
    s.add_event('dst_ip = 1.2.3.4')
    
    for event in s.search('1.2.3.4'):
        print event
    print '-'
    for event in s.search('src_ip'):
        print event
    print '-'
    for event in s.search('ip'):
        print event


if __name__ ==  '__main__':
    main()
